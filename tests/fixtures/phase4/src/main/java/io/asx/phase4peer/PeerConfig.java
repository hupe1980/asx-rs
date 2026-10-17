package io.asx.phase4peer;

import java.io.File;
import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The peer's configuration, read from {@code /config/peer.json}. Key material is PEM (certificate
 * and PKCS#8 key files) and is turned into BouncyCastle in-memory key stores by {@link Variant}:
 * the JDK's SunEC provider no longer implements brainpoolP256r1.
 */
public final class PeerConfig
{
  public List <VariantConfig> variants;

  public static final class VariantConfig
  {
    /** URL path segment: {@code POST /as4/{id}}. */
    public String id;
    /** phase4 profile id, e.g. {@code bdew} or {@code cef}. */
    public String profile;
    /** phase4's own party id and party id type. */
    public String partyId;
    public String partyIdType;
    /** phase4's signing pair (PEM). */
    public String signCert;
    public String signKey;
    /** phase4's encryption (decryption) pair (PEM). */
    public String encCert;
    public String encKey;
    /** Trusted certificates (PEM): the run's CA and the crate's certificates (direct trust). */
    public List <String> trust;
    /** The crate as phase4's partner. */
    public PartnerConfig partner;
  }

  public static final class PartnerConfig
  {
    public String partyId;
    public String partyIdType;
    public String signCert;
    public String encCert;
  }

  static PeerConfig read (final File aFile) throws IOException
  {
    final ObjectMapper aMapper = new ObjectMapper ().configure (DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    final PeerConfig ret = aMapper.readValue (aFile, PeerConfig.class);
    if (ret.variants == null || ret.variants.isEmpty ())
      throw new IOException ("peer.json declares no variant");
    return ret;
  }
}
