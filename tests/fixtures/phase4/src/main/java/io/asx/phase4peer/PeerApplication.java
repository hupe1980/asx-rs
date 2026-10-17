package io.asx.phase4peer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.helger.base.io.iface.IHasInputStream;
import com.helger.collection.commons.CommonsArrayList;
import com.helger.http.header.HttpHeaderMap;
import com.helger.mime.IMimeType;
import com.helger.phase4.CAS4Version;
import com.helger.phase4.attachment.IAS4IncomingAttachmentFactory;
import com.helger.phase4.incoming.AS4IncomingMessageMetadata;
import com.helger.phase4.incoming.AS4IncomingProfileSelectorConstant;
import com.helger.phase4.incoming.AS4IncomingReceiverConfiguration;
import com.helger.phase4.incoming.AS4RequestHandler;
import com.helger.phase4.incoming.AS4ServerInitializer;
import com.helger.phase4.incoming.IAS4ResponseAbstraction;
import com.helger.phase4.incoming.crypto.AS4IncomingSecurityConfiguration;
import com.helger.phase4.model.pmode.resolve.AS4DefaultPModeResolver;
import com.helger.servlet.mock.MockServletContext;
import com.helger.web.scope.mgr.WebScopeManager;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * asx-phase4-peer: phase4 as an AS4 counterparty for the asx-rs interop job.
 * <ul>
 * <li>{@code POST /as4/{variant}} - phase4's {@link AS4RequestHandler} with the variant's crypto
 * factories, a P-Mode resolver building from the profile's own template and an incoming profile
 * selector fixed to the variant's profile. The response is phase4's, unaltered.</li>
 * <li>{@code /control/*} - health, version, send (phase4's own profile sender), inbox.</li>
 * </ul>
 * The HTTP server is the JDK's: the AS4 handler needs no servlet container (the servlet in phase4 is
 * a thin adapter around the same {@link AS4RequestHandler}).
 */
public final class PeerApplication
{
  static final ObjectMapper JSON = new ObjectMapper ();
  static final Map <String, Variant> VARIANTS = new LinkedHashMap <> ();

  private PeerApplication ()
  {}

  public static void main (final String [] args) throws Exception
  {
    String sConfig = "/config/peer.json";
    for (final String a : args)
      if (a.startsWith ("--peer.config="))
        sConfig = a.substring ("--peer.config=".length ());

    // BrainpoolP256r1 needs BouncyCastle (SunEC dropped it); position 2 as in phase4's own tests.
    Security.insertProviderAt (new BouncyCastleProvider (), 2);

    WebScopeManager.onGlobalBegin (MockServletContext.create ());
    AS4ServerInitializer.initAS4Server ();
    Runtime.getRuntime ().addShutdownHook (new Thread ( () -> {
      AS4ServerInitializer.shutdownAS4Server ();
      WebScopeManager.onGlobalEnd ();
    }));

    final PeerConfig aConfig = PeerConfig.read (new File (sConfig));
    for (final PeerConfig.VariantConfig c : aConfig.variants)
    {
      final Variant v = new Variant (c);
      VARIANTS.put (v.id, v);
      System.out.println ("asx-phase4-peer: variant '" + v.id + "' -> phase4 profile '" + v.profileId + "'");
    }

    final HttpServer aServer = HttpServer.create (new InetSocketAddress (8080), 64);
    aServer.setExecutor (Executors.newFixedThreadPool (8));
    aServer.createContext ("/as4/", PeerApplication::handleAs4);
    aServer.createContext ("/control/", ControlHandler::handle);
    aServer.start ();
    System.out.println ("asx-phase4-peer: phase4 " + CAS4Version.BUILD_VERSION + " listening on :8080");
  }

  static String phase4Version ()
  {
    return CAS4Version.BUILD_VERSION;
  }

  /** The peer revision (pom version, e.g. 4.8.1-r1) from this JAR's manifest. */
  static String manifestVersion ()
  {
    return PeerApplication.class.getPackage ().getImplementationVersion ();
  }

  private static void handleAs4 (final HttpExchange ex) throws IOException
  {
    try
    {
      final String sId = ex.getRequestURI ().getPath ().substring ("/as4/".length ());
      final Variant v = VARIANTS.get (sId);
      if (v == null || !"POST".equals (ex.getRequestMethod ()))
      {
        send (ex, 404, "text/plain", ("no AS4 variant '" + sId + "'").getBytes (StandardCharsets.UTF_8));
        return;
      }
      final HttpHeaderMap aHeaders = new HttpHeaderMap ();
      ex.getRequestHeaders ().forEach ( (k, vals) -> vals.forEach (val -> aHeaders.addHeader (k, val)));

      final AS4IncomingMessageMetadata aMeta = AS4IncomingMessageMetadata.createForRequest ()
                                                                         .setRemoteAddr (ex.getRemoteAddress ()
                                                                                           .getAddress ()
                                                                                           .getHostAddress ())
                                                                         .setRemotePort (ex.getRemoteAddress ()
                                                                                           .getPort ())
                                                                         .setHttpHeaders (aHeaders);
      final Response aResp = new Response ();
      try (final AS4RequestHandler h = new AS4RequestHandler (aMeta))
      {
        h.setCryptoFactorySign (v.signFactory);
        h.setCryptoFactoryCrypt (v.cryptFactory);
        h.setPModeResolver (new AS4DefaultPModeResolver (v.profileId));
        h.setIncomingProfileSelector (new AS4IncomingProfileSelectorConstant (v.profileId, true));
        h.setIncomingAttachmentFactory (IAS4IncomingAttachmentFactory.DEFAULT_INSTANCE);
        h.setIncomingSecurityConfiguration (AS4IncomingSecurityConfiguration.createDefaultInstance ());
        h.setIncomingReceiverConfiguration (new AS4IncomingReceiverConfiguration ());
        h.setProcessorSupplier ( () -> new CommonsArrayList <> (new InboxSpi (v.id)));
        h.handleRequest (ex.getRequestBody (), aHeaders, aResp);
      }
      aResp.writeTo (ex);
    }
    catch (final Exception e)
    {
      e.printStackTrace ();
      send (ex, 500, "text/plain", ("peer error: " + e).getBytes (StandardCharsets.UTF_8));
    }
  }

  static void send (final HttpExchange ex, final int nStatus, final String sContentType, final byte [] aBody)
                                                                                                             throws IOException
  {
    ex.getResponseHeaders ().set ("Content-Type", sContentType);
    ex.sendResponseHeaders (nStatus, aBody.length == 0 ? -1 : aBody.length);
    try (OutputStream aOS = ex.getResponseBody ())
    {
      aOS.write (aBody);
    }
  }

  /** Collects what phase4 writes into its response abstraction. */
  static final class Response implements IAS4ResponseAbstraction
  {
    int m_nStatus = 200;
    String m_sMimeType;
    Charset m_aCharset;
    byte [] m_aBody = new byte [0];
    final List <String []> m_aHeaders = new ArrayList <> ();

    public void setContent (final byte [] aBytes, final Charset aCharset)
    {
      m_aBody = aBytes;
      m_aCharset = aCharset;
    }

    public void setContent (final HttpHeaderMap aHeaderMap, final IHasInputStream aHasIS)
    {
      aHeaderMap.forEachSingleHeader ( (k, val) -> m_aHeaders.add (new String [] { k, val }), false);
      try (InputStream aIS = aHasIS.getInputStream (); ByteArrayOutputStream aBOS = new ByteArrayOutputStream ())
      {
        aIS.transferTo (aBOS);
        m_aBody = aBOS.toByteArray ();
      }
      catch (final IOException e)
      {
        throw new IllegalStateException (e);
      }
    }

    public void setMimeType (final IMimeType aMimeType)
    {
      m_sMimeType = aMimeType.getAsString ();
    }

    public void setStatus (final int nStatusCode)
    {
      m_nStatus = nStatusCode;
    }

    void writeTo (final HttpExchange ex) throws IOException
    {
      String sContentType = null;
      for (final String [] h : m_aHeaders)
      {
        if (h[0].equalsIgnoreCase ("Content-Type"))
          sContentType = h[1];
        else
          if (!h[0].equalsIgnoreCase ("Content-Length"))
            ex.getResponseHeaders ().add (h[0], h[1]);
      }
      if (sContentType == null && m_sMimeType != null)
        sContentType = m_sMimeType + (m_aCharset != null && !m_sMimeType.contains ("charset") ? "; charset=" +
                                                                                                 m_aCharset.name ()
                                                                                               : "");
      if (sContentType == null)
        sContentType = "application/octet-stream";
      send (ex, m_nStatus, sContentType, m_aBody);
    }
  }

  static String b64 (final byte [] a)
  {
    return a == null ? null : Base64.getEncoder ().encodeToString (a);
  }
}
