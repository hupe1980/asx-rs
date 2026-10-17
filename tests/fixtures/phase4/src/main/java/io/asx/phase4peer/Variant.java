package io.asx.phase4peer;

import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.helger.phase4.crypto.AS4CryptoFactoryInMemoryKeyStore;
import com.helger.phase4.crypto.IAS4CryptoFactory;
import com.helger.phase4.mgr.MetaAS4Manager;
import com.helger.phase4.profile.IAS4Profile;
import com.helger.security.keystore.EKeyStoreType;

/**
 * One profile variant: phase4's key material for it, its trust store, the crate as partner. The
 * key stores are BouncyCastle in-memory PKCS#12 stores (as phase4's own Brainpool test does).
 */
public final class Variant
{
  private static final char [] KEY_PASSWORD = "peer".toCharArray ();

  final String id;
  final String profileId;
  final IAS4Profile profile;
  final String partyId;
  final String partyIdType;
  final X509Certificate signCert;
  final X509Certificate encCert;
  final IAS4CryptoFactory signFactory;
  final IAS4CryptoFactory cryptFactory;
  final String partnerPartyId;
  final String partnerPartyIdType;
  final X509Certificate partnerSignCert;
  final X509Certificate partnerEncCert;

  Variant (final PeerConfig.VariantConfig c) throws Exception
  {
    id = require (c.id, "id");
    profileId = require (c.profile, "profile");
    profile = MetaAS4Manager.getProfileMgr ().getProfileOfID (profileId);
    if (profile == null)
      throw new IllegalArgumentException ("variant '" + id + "': unknown phase4 profile '" + profileId + "'");
    partyId = require (c.partyId, "partyId");
    partyIdType = c.partyIdType;
    if (c.partner == null)
      throw new IllegalArgumentException ("variant '" + id + "': partner missing");
    partnerPartyId = require (c.partner.partyId, "partner.partyId");
    partnerPartyIdType = c.partner.partyIdType;

    signCert = readCert (require (c.signCert, "signCert"));
    encCert = readCert (require (c.encCert, "encCert"));
    partnerSignCert = readCert (require (c.partner.signCert, "partner.signCert"));
    partnerEncCert = readCert (require (c.partner.encCert, "partner.encCert"));

    final KeyStore aTrust = EKeyStoreType.PKCS12.getKeyStore ("BC");
    aTrust.load (null, null);
    int i = 0;
    final List <String> aTrustFiles = c.trust == null ? new ArrayList <> () : c.trust;
    for (final String sFile : aTrustFiles)
      aTrust.setCertificateEntry ("trusted" + (i++), readCert (sFile));

    signFactory = new AS4CryptoFactoryInMemoryKeyStore (keyStore ("sign", signCert, readKey (require (c.signKey,
                                                                                                      "signKey"))),
                                                        "sign",
                                                        KEY_PASSWORD,
                                                        aTrust);
    cryptFactory = new AS4CryptoFactoryInMemoryKeyStore (keyStore ("enc", encCert, readKey (require (c.encKey,
                                                                                                     "encKey"))),
                                                         "enc",
                                                         KEY_PASSWORD,
                                                         aTrust);
  }

  private static String require (final String s, final String sName)
  {
    if (s == null || s.isEmpty ())
      throw new IllegalArgumentException ("peer.json: '" + sName + "' is required");
    return s;
  }

  private static KeyStore keyStore (final String sAlias, final X509Certificate aCert, final PrivateKey aKey)
                                                                                                             throws Exception
  {
    final KeyStore ret = EKeyStoreType.PKCS12.getKeyStore ("BC");
    ret.load (null, null);
    ret.setKeyEntry (sAlias, aKey, KEY_PASSWORD, new Certificate [] { aCert });
    return ret;
  }

  static X509Certificate readCert (final String sFile) throws Exception
  {
    final CertificateFactory aCF = CertificateFactory.getInstance ("X.509", "BC");
    try (final InputStream aIS = Files.newInputStream (Path.of (sFile)))
    {
      return (X509Certificate) aCF.generateCertificate (aIS);
    }
  }

  static PrivateKey readKey (final String sFile) throws IOException
  {
    final Object aObj;
    try (final Reader aReader = new FileReader (sFile); final PEMParser aParser = new PEMParser (aReader))
    {
      aObj = aParser.readObject ();
    }
    final PrivateKeyInfo aInfo = aObj instanceof final PEMKeyPair p ? p.getPrivateKeyInfo ()
                                                                    : PrivateKeyInfo.getInstance (aObj);
    return new JcaPEMKeyConverter ().setProvider ("BC").getPrivateKey (aInfo);
  }
}
