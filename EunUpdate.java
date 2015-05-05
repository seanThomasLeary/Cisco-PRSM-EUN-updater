// this line is from the seanThomasLeary user
package eun.update;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.*;
import java.util.*;

import javax.net.ssl.*;

import org.json.JSONArray;
import org.json.JSONObject;


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

    // sensor uri, the IP and protocol part
    String uriIPSegment;

    // sensor uri, the db retrieval part
    String uriGetPageSegment;

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

    static HashMap<String, String> eunTypes = new HashMap<String, String>();

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

        // init the euntypes
        EunUpdate.eunTypes.put("WebReputation", "/api/configure/customeun/CustomEUN/geteunbytype/1/1.json/");
        EunUpdate.eunTypes.put("FileType", "/api/configure/customeun/CustomEUN/geteunbytype/2/1.json/");
        EunUpdate.eunTypes.put("UrlFiltering", "/api/configure/customeun/CustomEUN/geteunbytype/4/1.json/");
        EunUpdate.eunTypes.put("Application", "/api/configure/customeun/CustomEUN/geteunbytype/8/1.json/");
        EunUpdate.eunTypes.put("Destination", "/api/configure/customeun/CustomEUN/geteunbytype/16/1.json/");
        EunUpdate.eunTypes.put("Warning", "/api/configure/customeun/CustomEUN/geteunbytype/64/2.json/");
        EunUpdate.eunTypes.put("Authentication", "/api/configure/customeun/CustomEUN/geteunbytype/128/3.json/");

    }

    public static void usage () {
        System.out.println("EunUpdate 21 Mar, 2015");
        System.out.println("Usage:");
        System.out.println("   EunUpdate sensorURL eunType -u user/passwd [-d filename] [-v] ");
        System.out.println("    -u sensor username and password, separated by the / char");
        System.out.println("    -v Verbose for additional messages.");
        System.out.println("    -m MessageFilename the name of the file which contains the new message");
        System.out.println("   eunType must be one of");
        System.out.println("       WebReputation");
        System.out.println("       FileType");
        System.out.println("       UrlFiltering");
        System.out.println("       Application [default]");
        System.out.println("       Destination");
        System.out.println("       Warning");
        System.out.println("       Authentication");
        System.out.println("   EunUpdate retrieves a specified EUN record and optionally updates the message.");
        System.out.println("   If -d is not specified, the record is only retrieved.");
        System.out.println("Example: update the EUN detail text for URL-filtering");
        System.out.println("   java EunUpdate https://192.168.1.1 Application -u cisco/password -m ./myfile.txt");
    }

     /**
     * Main entry point
     * @param args A list of command line parameters
     */
     public static void main (String[] args)
     {
         // protocol:ip and euntype is required
         if (args.length < 3) {
             usage();
             return;
         }

         boolean verbose = false;
         String user = new String();
         String password = new String();
         String updateFile = new String();

         int acount = args.length - 1;
         int i = 1;
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
             } else if ("-m".equals(args[1+i+0].toLowerCase())) {
                 if ((i+1) < acount)  {
                     updateFile = new String(args[1+i+1]).toLowerCase();
                     i += 2;
                 } else {
                     System.out.println("too few filename params");
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
         String ipSegment = args[0];
         String eunType = args[1];
         String uriGetPageSegment = null;
         // validate the eun type
         for (String eun : eunTypes.keySet()) {
             if (eun.toLowerCase().startsWith(eunType.toLowerCase())) {
                 if (uriGetPageSegment == null) {
                     uriGetPageSegment = eunTypes.get(eun);
                 } else {
                     System.out.println("Ambiguous eun type [" +eunType+ "]");
                     System.out.println(FOR_HELP_TYPE);
                     return;
                 }
             }
         }
         if (uriGetPageSegment == null) {
             uriGetPageSegment = eunTypes.get("Application");
         }
         EunUpdate eunUpdate = new EunUpdate(ipSegment, uriGetPageSegment, 
                 user, password, updateFile, verbose);
         eunUpdate.processUpdate();

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
     public EunUpdate (String ipSegment, String getPageSegment, 
             String sensorUsername, String sensorPassword, 
             String updateFile, boolean verbose) {
         this.uriIPSegment = ipSegment;
         this.uriGetPageSegment = getPageSegment;
         this.sensorUsername = new StringBuilder(sensorUsername);
         this.sensorPassword = new StringBuilder(sensorPassword);
         if (updateFile.length() > 0) {
             this.updateFile = updateFile;
         }
         this.verbose = verbose;
         sensorXmlMsg = new StringBuilder();

     }


    private void processUpdate() {
        /**
         * Login to device
         */
        StringBuilder authenticationUri= 
                new StringBuilder(uriIPSegment+"/authentication/login/");
        sensorXmlMsg = new StringBuilder("username="+sensorUsername+
                "&password="+sensorPassword+"&next=\"\"");
        StringBuilder authStrBuilder = new StringBuilder();
        boolean ok = processSensorRequest(
                authenticationUri.toString(), authStrBuilder);
        if (!ok) {
            System.out.println("Failed to authenticate");
            return;
        }

        /**
         * Retrieve the page
         */
        StringBuilder getPageUri =
                new StringBuilder(uriIPSegment+uriGetPageSegment);
        sensorXmlMsg = new StringBuilder();
        StringBuilder getPageStrBuilder = new StringBuilder();
        ok = processSensorRequest(getPageUri.toString(), getPageStrBuilder);
        if (!ok) {
            System.out.println("Failed to authenticate");
            return;
        }

        /**
         * Parse the response
         */
        JSONObject jsonObject = new JSONObject(getPageStrBuilder.toString());
        if (jsonObject.has("message")) {
            System.out.println("Message found: ");
            System.out.println(jsonObject.getString("message"));
        } else {
            System.out.println("Unable to find expected message");
            return;
        }

        /**
         * Check for the file update
         */
        if (updateFile == null) {
            System.out.println("No message file specified");
            return;
        }
        String newMessage = null;
        try {
            if (updateFile != null) {
                byte[] encoded = Files.readAllBytes(Paths.get(updateFile));
                newMessage = new String(encoded);
            }
        } catch (IOException e) {
            System.out.println("Unable to read " + updateFile);
            return;
        }
        if (newMessage == null || newMessage.length() == 0) {
            System.out.println("Update file was empty");
            return;
        }
        System.out.println("new message: "+newMessage);
        jsonObject.put("message", newMessage);

        /**
         * Update sensor with new eun message
         */
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
                 System.out.println("\nRequest URI [" +uriIPSegment+ "]\n");
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

