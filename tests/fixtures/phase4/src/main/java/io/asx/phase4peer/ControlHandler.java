package io.asx.phase4peer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.helger.mime.IMimeType;
import com.helger.mime.parse.MimeTypeParser;
import com.helger.phase4.CAS4;
import com.helger.phase4.attachment.AS4OutgoingAttachment;
import com.helger.phase4.bdew.Phase4BDEWSender;
import com.helger.phase4.crypto.ECryptoKeyAgreementMethod;
import com.helger.phase4.crypto.ECryptoKeyDerivationMethod;
import com.helger.phase4.crypto.ECryptoKeyIdentifierType;
import com.helger.phase4.crypto.ECryptoKeyWrapAlgorithm;
import com.helger.phase4.messaging.http.HttpRetrySettings;
import com.helger.phase4.profile.bdew.BDEWPMode;
import com.helger.phase4.sender.EAS4UserMessageSendResult;
import com.sun.net.httpserver.HttpExchange;

/** {@code /control/*}: the harness's handle on phase4 (contracts: container-contract.md). */
final class ControlHandler
{
  private ControlHandler ()
  {}

  static void handle (final HttpExchange ex) throws IOException
  {
    final String sPath = ex.getRequestURI ().getPath ();
    final String sMethod = ex.getRequestMethod ();
    try
    {
      if (sPath.equals ("/control/health") && sMethod.equals ("GET"))
        json (ex, 200, Map.of ("status", "UP"));
      else
        if (sPath.equals ("/control/version") && sMethod.equals ("GET"))
          json (ex, 200, version ());
        else
          if (sPath.equals ("/control/send") && sMethod.equals ("POST"))
            sendMessage (ex);
          else
            if (sPath.equals ("/control/inbox") && sMethod.equals ("GET"))
              json (ex, 200, new ArrayList <> (InboxSpi.INBOX.values ()));
            else
              if (sPath.startsWith ("/control/inbox/") && sMethod.equals ("GET"))
              {
                final Map <String, Object> aEntry = InboxSpi.INBOX.get (sPath.substring ("/control/inbox/".length ()));
                if (aEntry == null)
                  json (ex, 404, Map.of ("error", "not delivered"));
                else
                  json (ex, 200, aEntry);
              }
              else
                json (ex, 404, Map.of ("error", "no such control endpoint"));
    }
    catch (final BadRequest e)
    {
      json (ex, 400, Map.of ("error", e.getMessage ()));
    }
    catch (final Exception e)
    {
      e.printStackTrace ();
      json (ex, 500, Map.of ("error", String.valueOf (e)));
    }
  }

  private static Map <String, Object> version ()
  {
    final Map <String, Object> ret = new LinkedHashMap <> ();
    ret.put ("phase4", PeerApplication.phase4Version ());
    ret.put ("peer", PeerApplication.manifestVersion ());
    ret.put ("java", System.getProperty ("java.version"));
    ret.put ("bouncycastle", new BouncyCastleProvider ().getVersionStr ());
    ret.put ("profiles", new ArrayList <> (PeerApplication.VARIANTS.keySet ()));
    // r3: the container's wall clock, so the harness can refuse a skewed Docker VM clock
    // (WSS4J rejects a wsu:Timestamp more than 60 s in the future).
    ret.put ("nowEpochMillis", Long.valueOf (System.currentTimeMillis ()));
    return ret;
  }

  static final class BadRequest extends Exception
  {
    BadRequest (final String s)
    {
      super (s);
    }
  }

  private static String text (final JsonNode n, final String sField, final boolean bRequired) throws BadRequest
  {
    final JsonNode v = n.get (sField);
    if (v == null || v.isNull ())
    {
      if (bRequired)
        throw new BadRequest ("'" + sField + "' is required");
      return null;
    }
    return v.asText ();
  }

  private static void sendMessage (final HttpExchange ex) throws Exception
  {
    final JsonNode aReq;
    try (InputStream aIS = ex.getRequestBody ())
    {
      aReq = PeerApplication.JSON.readTree (aIS);
    }
    catch (final IOException e)
    {
      throw new BadRequest ("malformed JSON: " + e.getMessage ());
    }
    final Variant v = PeerApplication.VARIANTS.get (text (aReq, "variant", true));
    if (v == null)
      throw new BadRequest ("unknown variant");
    if (!"bdew".equals (v.profileId))
      throw new BadRequest ("send is implemented for the bdew profile only (cef follows post-M1)");
    final String sToUrl = text (aReq, "toUrl", true);
    final String sMessageId = text (aReq, "messageId", true);
    final boolean bPing = aReq.path ("ping").asBoolean (false);
    final boolean bEncrypt = aReq.path ("encrypt").asBoolean (false);
    // r3: explicit "service"/"action" override the ping / business defaults. Phase4BDEWSender
    // (isEveryRequiredFieldSet, 4.8.1 :181-189) lets exactly the pathSwitch actions
    // requestSwitch/confirmSwitch go without a payload; any other payload-less send is refused
    // there (result FAILURE_MISSING_REQUIRED_FIELD or similar), not here.
    final String sServiceReq = text (aReq, "service", false);
    final String sActionReq = text (aReq, "action", false);
    final String sService = sServiceReq != null ? sServiceReq
                                                : bPing ? BDEWPMode.SERVICE_TEST : BDEWPMode.SERVICE_MARKTPROZESSE;
    final String sAction = sActionReq != null ? sActionReq
                                              : bPing ? BDEWPMode.ACTION_TEST_SERVICE : BDEWPMode.ACTION_DEFAULT;
    final List <AS4OutgoingAttachment.Builder> aPayloads = new ArrayList <> ();
    for (final JsonNode p : aReq.path ("payloads"))
    {
      final IMimeType aMT = MimeTypeParser.safeParseMimeType (text (p, "mimeType", true));
      if (aMT == null)
        throw new BadRequest ("bad mimeType");
      aPayloads.add (AS4OutgoingAttachment.builder ()
                                          .data (Base64.getDecoder ().decode (text (p, "base64", true)))
                                          .mimeType (aMT));
    }

    final AtomicReference <byte []> aRaw = new AtomicReference <> ();
    final AtomicReference <String> aRawType = new AtomicReference <> ();
    final AtomicReference <String> aError = new AtomicReference <> ();

    final Phase4BDEWSender.BDEWUserMessageBuilder b = Phase4BDEWSender.builder ()
                                                                      .cryptoFactorySign (v.signFactory)
                                                                      .cryptoFactoryCrypt (v.cryptFactory)
                                                                      .fromPartyIDType (v.partyIdType)
                                                                      .fromPartyID (v.partyId)
                                                                      .fromRole (CAS4.DEFAULT_INITIATOR_URL)
                                                                      .toPartyIDType (v.partnerPartyIdType)
                                                                      .toPartyID (v.partnerPartyId)
                                                                      .toRole (CAS4.DEFAULT_RESPONDER_URL)
                                                                      .service (sService)
                                                                      .action (sAction)
                                                                      .endpointURL (sToUrl)
                                                                      .messageID (sMessageId)
                                                                      .httpRetrySettings (new HttpRetrySettings ().setMaxRetries (0))
                                                                      .rawResponseConsumer (r -> {
                                                                        aRaw.set (r.getResponseContent ());
                                                                        if (r.getResponseHeaders () != null)
                                                                          aRawType.set (r.getResponseHeaders ()
                                                                                         .getFirstHeaderValue ("Content-Type"));
                                                                      });
    // Encryption is on exactly when a receiver certificate is set (AS4CryptParams#isCryptEnabled).
    if (bEncrypt)
    {
      b.receiverCertificate (v.partnerEncCert);
      // r2: Phase4BDEWSender 4.8.1 only sets ECDH_ES_KEYWRAP_AES_128 as a key *transport*
      // algorithm with setEncryptSymmetricSessionKey(false) and no key agreement method, so
      // AS4Encryptor writes EncryptedData with an empty ds:KeyInfo and no EncryptedKey. BDEW
      // (AS4-Profil 2.2.6.2.2) needs ECDH-ES key agreement + ConcatKDF + kw-aes128 with the
      // session key wrapped in an xenc:EncryptedKey; the recipient stays X509 SKI (the BDEW
      // builder default for crypt).
      b.cryptParams ()
       .setKeyAgreementMethod (ECryptoKeyAgreementMethod.ECDH_ES)
       .setKeyDerivationMethod (ECryptoKeyDerivationMethod.CONCAT_KDF)
       .setKeyWrapAlgorithm (ECryptoKeyWrapAlgorithm.AES_128)
       .setKeyIdentifierType (ECryptoKeyIdentifierType.X509_SKI_KEY_IDENTIFIER)
       .setEncryptSymmetricSessionKey (true);
    }
    if (!aPayloads.isEmpty ())
    {
      b.payload (aPayloads.get (0), null);
      for (int i = 1; i < aPayloads.size (); ++i)
        b.addAttachment (aPayloads.get (i).compressionGZIP ());
    }
    final EAS4UserMessageSendResult eResult = b.sendMessageAndCheckForReceipt (e -> {
      e.printStackTrace ();
      aError.set (String.valueOf (e));
    });

    final Map <String, Object> aResp = new LinkedHashMap <> ();
    aResp.put ("result", eResult.name ());
    aResp.put ("messageId", sMessageId);
    aResp.put ("service", sService);
    aResp.put ("action", sAction);
    aResp.put ("receiptBase64", PeerApplication.b64 (aRaw.get ()));
    aResp.put ("receiptContentType", aRawType.get ());
    aResp.put ("error", aError.get ());
    json (ex, 200, aResp);
  }

  static void json (final HttpExchange ex, final int nStatus, final Object aBody) throws IOException
  {
    PeerApplication.send (ex,
                          nStatus,
                          "application/json",
                          PeerApplication.JSON.writeValueAsString (aBody).getBytes (StandardCharsets.UTF_8));
  }
}
