package eun.update;

import java.io.*;
import java.net.*;
import java.security.cert.*;
import java.util.*;

import javax.net.ssl.*;


/**
 * Workaround for CSCut17139 so users can update the EUN message on 
 * CX sensors.
 * This bug prevents the user from updating the End User Notification pages on
 * Cisco CX sensors. The HTML which is normally embedded in the detail text 
 * becomes visible and does not perform its markup function. The text gets 
 * saved to the config database and causes display problems in the actual 
 * EUN pages that are rendered to end users. Normally this type of problem 
 * could be addressed by a few Curl messages. However in this case the 
 * EUN update also includes the caption text, EUN type, image binary, 
 * and other fields, since the fields of the database record are updated 
 * all together as a blob.
 * 
 * To allow users to work around the problem, the entire db record has to be 
 * retrieved, and then sent back in an update, with only the text changed. 
 * This will at least fix the problem where users have inadvertently modified 
 * the EUN detail text. Future revisions will allow users to modify other 
 * fields in the db record.
 */
public class EunUpdate {
    private static final String FOR_HELP_TYPE = 
            "For help, type \"java EunUpdater\"";
    
    // Using the -v  parameter sets verbose=true for debug-level output
    boolean verbose = false;

    // sensor uri, the part which is common to all commands
    StringBuilder uri;
    
    // POST request xml content data
    StringBuilder sensorXmlMsg;

    // sensor username
    StringBuilder sensorUsername;

    // sensor password
    StringBuilder sensorPassword;

    // Session cookie returned by the server
    StringBuilder sessionCookie = new StringBuilder();

    // detail text file
    String updateFile;

    // EUN page type 
    String eunType;

    // installs the certification and hostname verification objects
    static
    {
        // create and install a trust manager that accepts all certs
        X509TrustManager tm = new MyX509TrustManager();
        TrustManager[] trustAllCerts = {tm};
        try {
            SSLContext sc = SSLContext.getInstance( "TLS" );
            sc.init( null, trustAllCerts, new java.security.SecureRandom() );
            HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );
        }   catch ( Exception e ) { }
        // create and install a host name verifier that accepts all hosts
        HostnameVerifier hv = new MyHostnameVerifier();
        try {
            HttpsURLConnection.setDefaultHostnameVerifier( hv );
        }   catch ( Exception e ) { }
    }

    public static void usage () {
        System.out.println("EunUpdate 21 Mar, 2015");
        System.out.println("Usage:");
        System.out.println("   EunUpdate sensorURL -u user/passwd [-d filename] [-t type] [-v] ");
        System.out.println("    -u sensor username and password, separated by the / char");
        System.out.println("    -v Verbose for additional messages.");
        System.out.println("    -d detailTextFilename the name of the file which contains the new detail text");
        System.out.println("    -t type of EUN page to update");
        System.out.println("       1=");
        System.out.println("       2=");
        System.out.println("       3=");
        System.out.println("       4=");
        System.out.println("       5=");
        System.out.println("       6=");
        System.out.println("       7=");
        System.out.println("       8= [default]");
        System.out.println("   EunUpdate retrieves a specified EUN record and optionally updates the detail text.");
        System.out.println("   If -d is not specified, the record is only retrieved.");
        System.out.println("Example: update the EUN detail text for URL-filtering");
        System.out.println("   java EunUpdate https://192.168.1.1 -u cisco/password -t 8 -d myfile.txt");
    }

     /**
     * Main entry point
     * @param args A list of command line parameters
     */
     public static void main (String[] args)
     {
         // uri is required
         if (args.length < 2) {
             usage();
             return;
         }

         boolean verbose = false;
         String user = new String();
         String password = new String();
         String updateFile = new String();
         String eunType = "8";

         int acount = args.length - 1;
         int i = 0;
         while (i < acount) {
             if ("-u".equals(args[1+i+0].toLowerCase())) {
                 if ((i+1) < acount)  {
                     String userPass = new String(args[1+i+1]);
                     String [] sbuf = userPass.split("/");
                     if (sbuf.length > 0)
                         user = sbuf[0];
                     if (sbuf.length > 1)
                         password = sbuf[1];
                     if (sbuf.length > 2) {
                         System.out.println("Too many user/password parameters");
                         System.out.println(FOR_HELP_TYPE);
                         return;
                     }
                     i += 2;
                 } else {
                     System.out.println("too few params for user/password");
                     System.out.println(FOR_HELP_TYPE);
                     return;
                 }
             } else if ("-d".equals(args[1+i+0].toLowerCase())) {
                 if ((i+1) < acount)  {
                     updateFile = new String(args[1+i+1]).toLowerCase();
                     i += 2;
                 } else {
                     System.out.println("too few filename params");
                     System.out.println(FOR_HELP_TYPE);
                     return;
                 }
             } else if ("-t".equals(args[1+i+0].toLowerCase())) {
                 if ((i+1) < acount)  {
                     eunType = new String(args[1+i+1]).toLowerCase();
                     i += 2;
                     try {
                         int t = Integer.valueOf(eunType);
                         if (t < 1 || t > 9) {
                             System.out.println("EUN type must be 1-8 inclusive");
                             System.out.println(FOR_HELP_TYPE);
                             return;
                         } 
                     } catch (Exception ignore) {
                         System.out.println("EUN type must be 1-8 inclusive");
                         System.out.println(FOR_HELP_TYPE);
                         return;
                     }
                 } else {
                     System.out.println("too few type params");
                     System.out.println(FOR_HELP_TYPE);
                     return;
                 }
             } else if ("-v".equals(args[1+i+0].toLowerCase())) {
                 verbose = true;
                 ++i;
             } else if ("-h".equals(args[1+i+0].toCharArray())) {
                 usage();
                 return;
             } else if ("--h".equals(args[1+i+0].toLowerCase())) {
                 usage();
                 return;
             } else if ("-help".equals(args[1+i+0].toLowerCase())) {
                 usage();
                 return;
             } else if ("--help".equals(args[1+i+0].toLowerCase())) {
                 usage();
                 return;
             } else if ("?".equals(args[1+i+0])) {
                 usage();
                 return;
             } else if ("-?".equals(args[1+i+0])) {
                 usage();
                 return;
             } else if ("--?".equals(args[1+i+0])) {
                 usage();
                 return;
             } else {
                 System.out.println("Unexpected parameter [" +args[1+i+0]+ "]");
                 System.out.println(FOR_HELP_TYPE);
                 return;
             }
         }
         /**
          * make sure either a user or a cookie is specified,
          * otherwise assume user just wants help
          */
         if (user.length() == 0) {
             usage();
             return;
         }

         // input params ok, start the EventCatcher
         String uri = args[0];
         EunUpdate eu = new EunUpdate(uri, user, password,
                 updateFile, eunType, verbose);
         eu.processUpdate();

     }

     /**
      * creates an EventCatcher with all values needed to update the EUN
      * @param uri common part of the uri for all requests
      * @param sensorUsername sensor username
      * @param sensorPassword sensor password
      * @param updateFile the detail text filename (optional)
      * @param eunType the EUN page type
      * @param verbose enable debug messages
      */
     public EunUpdate (String uri, String sensorUsername, String sensorPassword, 
             String updateFile, String eunType, boolean verbose) {
         this.uri = new StringBuilder(uri);
         this.sensorUsername = new StringBuilder(sensorUsername);
         this.sensorPassword = new StringBuilder(sensorPassword);
         this.updateFile = updateFile;
         this.eunType = eunType;
         this.verbose = verbose;
         sensorXmlMsg = new StringBuilder();
     }


    private void processUpdate() {
        /**
         * Login to device
         */
        StringBuilder authenticationUri= new StringBuilder(uri+"/authentication/login/");
        sensorXmlMsg = new StringBuilder("username="+sensorUsername+"&password="+sensorPassword+"&next=\"\"");
        StringBuilder str = new StringBuilder();
        boolean ok = processSensorRequest(authenticationUri.toString(), str);
        if (!ok) {
            System.out.println("Failed to authenticate");
            return;
        }
    }

    /**
     * Process a sensor request and store the response
     * @param requestUri the uri to use for this request
     * @param responseStringBuffer will contain the response text
     * @return true if successful, otherwise false 
     */
     private boolean processSensorRequest (String requestUri, StringBuilder response)
     {
         try {
             if (verbose) {
                 System.out.println("\nRequest URI [" +uri+ "]\n");
             }
             
             InputStream is = dispatchSensorMessage(requestUri, sensorXmlMsg.toString());
             InputStreamReader in =  new InputStreamReader(is);
             BufferedReader reader = new BufferedReader(in);
             String line = null;
             while((line = reader.readLine()) != null) {
                 response.append(line);
             }
             if (verbose) {
                 if (sessionCookie.length() > 0) {
                     System.out.println("SessionCookie [" +sessionCookie+ "]\n");
                 }
                 System.out.println("Response [" +response.toString()+ "]");
             }

             return true;
         }
         catch (Exception e) {
             System.out.println("Error when sending message to sensor [" +e.getMessage()+ "]");
             return false;
         }
     }

    /**
     * Dispatch a message to the sensor and opens a reader on the response
     * @param uri the complete URI string
     * @param xmlMsg contains the XML request data.
     * @param responseParameters output, contains the HTTP header parameter pairs.
     * @return The input stream for the response
     * @throws Exception
     */
     private InputStream dispatchSensorMessage (String uri, String xmlMsg) throws Exception
     {
         URL url = new URL(uri);
         HttpURLConnection httpConn = getURLobject(uri, xmlMsg, url);

         if (sessionCookie.length() > 0) {
             httpConn.setRequestProperty("Cookie", sessionCookie.toString());
             if (verbose) {
                 System.out.println("   key [Cookie]");
                 System.out.println("      value [" +sessionCookie+ "]");
             }
         }

         httpConn.connect();

         if (xmlMsg != null && xmlMsg.length() > 0)
         {
             OutputStreamWriter wr = new OutputStreamWriter( httpConn.getOutputStream() );
             wr.write(xmlMsg.toString());
             wr.flush();
             wr.close();
         }
         String cookieHeader = httpConn.getHeaderField("Set-Cookie");
         if(cookieHeader != null)
         {
             int index = cookieHeader.indexOf(";");
             if(index >= 0)
             {
                 sessionCookie = new StringBuilder(cookieHeader.substring(0, index));
             }
         }

         if (verbose) {
             System.out.println("Header response lines");
             Map<String, List<String>> map = httpConn.getHeaderFields();
             if (map != null) {
                 Set<String> keySet = map.keySet();
                 if (keySet != null) {
                     Iterator<String> it = keySet.iterator();
                     while (it.hasNext()) {
                         String key = it.next();
                         System.out.println("   key [" +key+ "]");
                         List<String> list = map.get(key);
                         if (list != null) {
                             Iterator<String> it1 = list.iterator();
                             while (it1.hasNext()) {
                                 String value = it1.next();
                                 System.out.println("         value [" +value+ "]");
                             }
                         }
                     }
                 }
             }
         }

         InputStream response;
         try {
             response =  httpConn.getInputStream();
             // httpConn.disconnect();
         } catch (IOException e) {
             System.out.println("exception");
             throw e;
         }

         return response;

     }

    /**
     * Builds a http header for a sensor request
     * @param uri the complete URI string for this sensor request
     * @param xmlMsg optional, the XML content for this request
     * @param url the URL object for this connection
     * @return an initialized HttpURLConnection
     * @throws exception with appropriate error msg if response document contains error msg.
     */
     private HttpURLConnection getURLobject (String uri, String xmlMsg, URL url) throws Exception
     {
         URLConnection urlcon = url.openConnection();
         HttpURLConnection conn = (HttpURLConnection) urlcon;
         //  ******** Filling of Default Request Header Properties  ************
         conn.setUseCaches( false );
         HttpURLConnection.setFollowRedirects( false );
         if (xmlMsg != null && xmlMsg.length() > 0)
             conn.setRequestMethod("POST");
         conn.setDoInput (true);
         conn.setDoOutput(true);

         // String encoding = null;

         conn.setRequestProperty( "Accept", "text/xml");
         conn.setRequestProperty( "Content-type", "xml/txt");
         conn.setRequestProperty( "Accept-Charset", "iso-8859-1,*,utf-8");
         conn.setRequestProperty( "User-Agent", "CIDS Client/4.0");
         conn.setRequestProperty( "Pragma", "no-cache");
         String xmlStr = "XMLHttpRequest";
         String contentTypeStr = "application/x-www-form-urlencoded";
         conn.setRequestProperty("X-Requested-With", xmlStr);
         conn.setRequestProperty("Content-Type", contentTypeStr);
         if (verbose) {
             // TODO: just get the data from conn 
             System.out.println("Header request lines");
             System.out.println("   key [Accept]");
             System.out.println("      value [text/xml]");
             System.out.println("   key [Content-type]");
             System.out.println("      value [xml/txt]");
             System.out.println("   key [Accept-Charset]");
             System.out.println("      value [iso-8859-1,*,utf-8]");
             System.out.println("   key [User-Agent]");
             System.out.println("      value [CIDS Client/4.0]");
             System.out.println("   key [Pragma]");
             System.out.println("      value [no-cache]");
             System.out.println("   key[X-Requested-With]");
             System.out.println("      value["+xmlStr+"]");
             System.out.println("   key[Content-Type]");
             System.out.println("      value["+contentTypeStr+"]");
         }

         return conn;
     }


}
    
//  **************  MYX509 TRUST MANAGER   ***************
/**
* This class performs trivial certificate checking - all certificates are accepted
*/
class MyX509TrustManager implements X509TrustManager
{
    /**
    * Trust all clients
    * @param chain the ceritficates to check
    * @param str the response
    */
    public void checkClientTrusted (X509Certificate[] chain, String str)
    {
    }

    /**
    * trust all servers
    * @param chain the ceritficates to check
    * @param str the response
    */
    public void checkServerTrusted (X509Certificate[] chain, String str)
    {
    }

    /**
    * there are no accepted issuers
    * @return null
    */
    public java.security.cert.X509Certificate[] getAcceptedIssuers ()
    {
        return null;
    }
}

//  **************  MYHOSTNAME VERIFIER ***************

/**
* This class performs trivial host name verification - all host names are accepted
*/
class  MyHostnameVerifier implements HostnameVerifier
{
    /**
    * trust all host names
    * @param urlHostname the host name to check
    * @param session the SSL session
    * @return always returns true
    */
    public boolean verify (String urlHostname, SSLSession session)
    {
        return true;
    }
}

