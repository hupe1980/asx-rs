package io.asx.phase4peer;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.w3c.dom.Node;

import com.helger.collection.commons.ICommonsList;
import com.helger.http.header.HttpHeaderMap;
import com.helger.phase4.attachment.WSS4JAttachment;
import com.helger.phase4.ebms3header.Ebms3SignalMessage;
import com.helger.phase4.ebms3header.Ebms3UserMessage;
import com.helger.phase4.error.AS4ErrorList;
import com.helger.phase4.incoming.IAS4IncomingMessageMetadata;
import com.helger.phase4.incoming.IAS4IncomingMessageState;
import com.helger.phase4.incoming.spi.AS4MessageProcessorResult;
import com.helger.phase4.incoming.spi.AS4SignalMessageProcessorResult;
import com.helger.phase4.incoming.spi.IAS4IncomingMessageProcessorSPI;
import com.helger.phase4.model.pmode.IPMode;

/**
 * phase4's application side: records what phase4 delivered (plaintext digests, the signing
 * certificate phase4 verified, whether it decrypted) and accepts it. phase4 does not invoke it for
 * a ping (test service) under profiles that do not pass pings through.
 */
public final class InboxSpi implements IAS4IncomingMessageProcessorSPI
{
  static final Map <String, Map <String, Object>> INBOX = new ConcurrentHashMap <> ();

  private final String m_sVariant;

  InboxSpi (final String sVariant)
  {
    m_sVariant = sVariant;
  }

  static String sha256Hex (final byte [] a) throws Exception
  {
    return HexFormat.of ().formatHex (MessageDigest.getInstance ("SHA-256").digest (a));
  }

  public AS4MessageProcessorResult processAS4UserMessage (final IAS4IncomingMessageMetadata aMeta,
                                                          final HttpHeaderMap aHttpHeaders,
                                                          final Ebms3UserMessage aUserMessage,
                                                          final IPMode aPMode,
                                                          final Node aPayload,
                                                          final ICommonsList <WSS4JAttachment> aAttachments,
                                                          final IAS4IncomingMessageState aState,
                                                          final AS4ErrorList aErrors)
  {
    try
    {
      final String sMessageId = aUserMessage.getMessageInfo ().getMessageId ();
      final List <Map <String, Object>> aParts = new ArrayList <> ();
      if (aAttachments != null)
        for (final WSS4JAttachment a : aAttachments)
        {
          final byte [] aBytes;
          try (final InputStream aIS = a.getSourceStream ())
          {
            aBytes = aIS.readAllBytes ();
          }
          final Map <String, Object> aPart = new LinkedHashMap <> ();
          aPart.put ("contentId", a.getId ());
          aPart.put ("mimeType", a.getUncompressedMimeType ());
          aPart.put ("sha256", sha256Hex (aBytes));
          aParts.add (aPart);
        }
      final X509Certificate aSigner = aState.getSigningCertificate ();
      final Map <String, Object> aEntry = new LinkedHashMap <> ();
      aEntry.put ("messageId", sMessageId);
      aEntry.put ("variant", m_sVariant);
      aEntry.put ("signingCertSha256", aSigner == null ? null : sha256Hex (aSigner.getEncoded ()));
      aEntry.put ("decrypted", Boolean.valueOf (aState.isSoapDecrypted ()));
      aEntry.put ("ping", Boolean.valueOf (aState.isPingMessage ()));
      aEntry.put ("service", aUserMessage.getCollaborationInfo ().getService ().getValue ());
      aEntry.put ("action", aUserMessage.getCollaborationInfo ().getAction ());
      aEntry.put ("parts", aParts);
      INBOX.put (sMessageId, aEntry);
      System.out.println ("asx-phase4-peer: delivered " + sMessageId + " (" + aParts.size () + " parts)");
      return AS4MessageProcessorResult.createSuccess ();
    }
    catch (final Exception ex)
    {
      ex.printStackTrace ();
      return AS4MessageProcessorResult.createFailure ();
    }
  }

  public AS4SignalMessageProcessorResult processAS4SignalMessage (final IAS4IncomingMessageMetadata aMeta,
                                                                  final HttpHeaderMap aHttpHeaders,
                                                                  final Ebms3SignalMessage aSignalMessage,
                                                                  final IPMode aPMode,
                                                                  final IAS4IncomingMessageState aState,
                                                                  final AS4ErrorList aErrors)
  {
    return AS4SignalMessageProcessorResult.createSuccess ();
  }

  public void processAS4ResponseMessage (final IAS4IncomingMessageMetadata aMeta,
                                         final IAS4IncomingMessageState aState,
                                         final String sResponseMessageID,
                                         final byte [] aResponseBytes,
                                         final boolean bResponsePayloadIsAvailable,
                                         final AS4ErrorList aErrors)
  {}
}
