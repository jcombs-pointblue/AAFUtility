/*
 * Author: Jerry Combs jcombs@pointbluetech.com
 * License: this code is public domain and may be used 
 * and modified in any way.
 * 
 */
package aafutility;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Hex;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import javax.net.ssl.*;
import java.net.Socket;
import java.security.cert.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.Iterator;
import java.util.Properties;
import org.json.JSONException;

public class AAFUtility
{

    static String endPointID;
    static String endPointSecret;
    static String adminID;
    static String adminPW;
    static String mode;
    static String debug = "true";
    static BufferedWriter logFile;
    static String dataFile;
    static String targetURL;
    static String userRepository = "";
    static String type = "";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception
    {
        //System.out.println("To Hex: " + Hex.encodeHexString(new String("12526").getBytes(StandardCharsets.UTF_8)));

        //System.out.println("cardHex: "+ encodeCardID("184","12281")); 
        init(args);
        if (!(type.equalsIgnoreCase("card") || type.equalsIgnoreCase("password") || type.equalsIgnoreCase("both")))
        {
            System.out.println("An incorrect load type was specified. The valid values are 'card', 'password', and 'both'");
            System.exit(-1);
        }

        String secretHash = getEndpointSecretHash(endPointID, endPointSecret);
        //System.out.println("ep secret: s" + secretHash);
        trustAllHosts();
        //System.out.println("all hosts trusted");
        String epSessionId = getEndPointSessionId(endPointID, secretHash);
        //System.out.println("ep session ID: " + epSessionId);

        String logonProcessId = getLoginSession(epSessionId, adminID);
        //System.out.println("processID: " + logonProcessId);
        String loginSessionId = doLogin(epSessionId, logonProcessId, adminPW);

        LocalDateTime time = LocalDateTime.now();

        logFile = new BufferedWriter(new FileWriter("AAFUtility-" + time.format(DateTimeFormatter.ofPattern("yyyyMMddhhmmss")) + ".log"));

        debug("opening data file");

        try (BufferedReader br = new BufferedReader(new FileReader(dataFile)))
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                String[] fields = line.split(",");
                String user = fields[0];
                String site = fields[1];
                String card = fields[2];
                String password = "";

                if (type.equalsIgnoreCase("password") || type.equalsIgnoreCase("both"))
                {
                    password = fields[3];

                }

                String targetUserId = userRepository + user;
                //Note single slash instead of double needed for using it in json as above
                String id = getTargetUserId(targetUserId, loginSessionId);
                //Check for bad ID
                if (id == null || id.equals(""))
                {
                    logToFile(targetUserId + " :Enrollment Failed: User Not Found");
                    continue;
                }

                if (type.equalsIgnoreCase("card") || type.equalsIgnoreCase("both"))
                {
                    String existingCardID = checkExistingCard(id, loginSessionId);

                    if (existingCardID.equals(""))
                    {
                        //debug("No existing card found, adding card");
                        String response = doCardEnroll(encodeCardID(site, card), loginSessionId, id);
                        if (response != null)
                        {
                            logToFile(targetUserId + " :Enrollment Failed");
                        }
                        else
                        {
                            logToFile(targetUserId + " :Enrollment Succeeded");
                        }

                    }
                    else
                    {
                        if (mode.equals("add"))
                        {
                            logToFile(targetUserId + " :Existing card found, you must delete the existing card first");

                        }
                        if (mode.equals("update"))
                        {
                            //remove template
                            unlinkTemplate(id, loginSessionId, existingCardID);

                            //add template
                            String response = doCardEnroll(encodeCardID(site, card), loginSessionId, id);
                            if (response != null)
                            {
                                logToFile(targetUserId + " :Enrollment Failed");
                            }
                            else
                            {
                                logToFile(targetUserId + " :Enrollment Succeeded");
                            }

                        }
                        if (mode.equals("clear"))
                        {
                            //remove template
                            //remove template
                            unlinkTemplate(id, loginSessionId, existingCardID);
                            logToFile(targetUserId + " :Deleted Card");
                        }

                    }

                }
                if (type.equalsIgnoreCase("password") || type.equalsIgnoreCase("both"))
                {
                    String existingPasswordID = checkExistingPassword(id, loginSessionId);

                    if (existingPasswordID.equals(""))
                    {
                        //debug("No existing card found, adding card");
                        String response = doPasswordEnroll(password, loginSessionId, id);
                        if (response != null)
                        {
                            logToFile(targetUserId + " :Password Enrollment Failed");
                        }
                        else
                        {
                            logToFile(targetUserId + " :Password Enrollment Succeeded");
                        }

                    }
                    else
                    {
                        if (mode.equals("add"))
                        {
                            logToFile(targetUserId + " :Existing password found, you must delete the existing password first");

                        }
                        if (mode.equals("update"))
                        {
                            //remove template
                            unlinkTemplate(id, loginSessionId, existingPasswordID);

                            //add template
                            String response = doPasswordEnroll(password, loginSessionId, id);
                            if (response != null)
                            {
                                logToFile(targetUserId + " :Password Enrollment Failed");
                            }
                            else
                            {
                                logToFile(targetUserId + " :Password Enrollment Succeeded");
                            }

                        }
                        if (mode.equals("clear"))
                        {
                            //remove template
                            //remove template
                            unlinkTemplate(id, loginSessionId, existingPasswordID);
                            logToFile(targetUserId + " :Deleted Password");
                        }
                    }

                }
            }

        }

        logFile.close();

    }

    public static void init(String[] args) throws Exception
    {
        if (args.length == 3)
        {
            System.out.println("using props from: " + args[0]);
            Properties props = new Properties();
            props.load(new FileReader(args[0]));

            endPointID = props.getProperty("endPointID");
            endPointSecret = props.getProperty("endPointSecret");
            adminID = "\"" + props.getProperty("adminID") + "\"";
            //System.out.println("admin ID: " + adminID);
            adminPW = args[2];
            mode = props.getProperty("mode"); //add,update,clear
            System.out.println("mode: " + mode);

            dataFile = args[1];
            targetURL = props.getProperty("targetURL");
            userRepository = props.getProperty("userRepository");
            debug = props.getProperty("debug").trim();
            //System.out.println("debug: " + debug);
            type = props.getProperty("type");
            System.out.println("load type: " + type);

        }
        else
        {
            System.out.println("please specify config file path, a path to data file, and password");
            System.exit(-1);

        }

    }

    public static void trustAllHosts()
    {
        try
        {
            TrustManager[] trustAllCerts = new TrustManager[]
            {
                new X509ExtendedTrustManager()
                {
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers()
                    {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType)
                    {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType)
                    {
                    }

                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] xcs, String string, Socket socket) throws CertificateException
                    {

                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] xcs, String string, Socket socket) throws CertificateException
                    {

                    }

                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] xcs, String string, SSLEngine ssle) throws CertificateException
                    {

                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] xcs, String string, SSLEngine ssle) throws CertificateException
                    {

                    }

                }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier()
            {
                @Override
                public boolean verify(String hostname, SSLSession session)
                {
                    return true;
                }
            };
            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static String getEndpointSecretHash(String id, String secret) throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        String salted_endpoint_id = (id + "randomSalt");
        byte[] endpoint_id_hash = digest.digest(salted_endpoint_id.getBytes(StandardCharsets.UTF_8));

        String salted_endpoint_secret = secret + (Hex.encodeHexString(endpoint_id_hash));

        byte[] msgBytes = digest.digest(salted_endpoint_secret.getBytes(StandardCharsets.UTF_8));
        return Hex.encodeHexString(msgBytes);

    }

    public static String getEndPointSessionId(String id, String secret)
    {
        //System.out.println("getting ep session ID");
        try
        {

            URL url = new URL(targetURL + "/api/v1/endpoints/" + id + "/sessions");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"salt\": \"randomSalt\",\"endpoint_secret_hash\": \"" + secret + "\",\"session_data\":{\"any\": { \"data\": [\"you\", \"want to store\", \"in session\"] }}}";

            debug(input);
            OutputStream os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());
            //need to getid from JSON
            // {"endpoint_session_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();

            String endpoint_session_id = json.getString("endpoint_session_id");
            debug(endpoint_session_id);
            //System.out.println("returning: " + endpoint_session_id);

            return endpoint_session_id;

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }
        System.out.println("Failed to get endpoint session. Check that endpoint is configured properly");
        throw new RuntimeException("Failed to get endpoint session. Check that endpoint is configured properly");
        
    }

    public static String getLoginSession(String epSessionId, String userID)
    {

        try
        {

            URL url = new URL(targetURL + "/api/v1/logon");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"method_id\": \"PASSWORD:1\",\"user_name\": " + userID + ",\"event\": \"Helpdesk\",\"endpoint_session_id\": \"" + epSessionId + "\"}";

            debug(input);
            OutputStream os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {

                StringBuilder sb = new StringBuilder();
                String output;
                BufferedReader br = new BufferedReader(new InputStreamReader(
                        (conn.getErrorStream())));
                while ((output = br.readLine()) != null)
                {
                    sb.append(output);

                }
                System.out.println(sb.toString());
                debug(sb.toString());
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode() + " : ");

            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
            String logon_process_id = json.getString("logon_process_id");
            debug(logon_process_id);
            return logon_process_id;

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }

        System.out.println("Failed to get login session. Check that admin user has a credential set for the Password method");
        throw new RuntimeException("Failed to get login session. Check that admin user has a credential set for the Password method");    

    }

    public static String doLogin(String epSessionId, String logonProcessId, String password)
    {

        try
        {

            URL url = new URL(targetURL + "/api/v1/logon/" + logonProcessId + "/do_logon");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"endpoint_session_id\": \"" + epSessionId + "\",\"response\": {\"answer\": \"" + password + "\"}}";

            //System.out.println(input);
            OutputStream os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
           
            String login_session_id = json.getString("login_session_id");
            debug(login_session_id);
            return login_session_id;

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }
        catch(JSONException e)
        {
          System.out.println("Failed to get login. Check the admin user password");
        throw new RuntimeException("Failed to get login. Check the admin user password");   
        }

        
      return null;
    }

    public static String doCardEnroll(String cardUID, String loginSessionId, String targetUserID)
    {

        try
        {
            URL url = new URL(targetURL + "/api/v1/enroll");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"method_id\": \"CARD:1\",\"login_session_id\":\"" + loginSessionId + "\"}";

            debug(input);
            OutputStream os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
            String enroll_process_id = json.getString("enroll_process_id");
            debug(enroll_process_id);

            url = new URL(targetURL + "/api/v1/enroll/" + enroll_process_id + "/do_enroll");
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            input = "{\"response\": {\"card_cert\": \"\",\"card_uid\": \"" + cardUID + "\"},\"login_session_id\": \"" + loginSessionId + "\"}";

            debug(input);
            os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            sb = new StringBuilder();

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            json = new JSONObject(sb.toString());

            conn.disconnect();
            String status = json.getString("status");
            String msg = json.getString("msg");
            debug("Response: " + status + " : " + msg);

            url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates");
            debug(url.toString());
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            input = "{\"login_session_id\": \"" + loginSessionId + "\",\"enroll_process_id\": \"" + enroll_process_id + "\",\"category_id\": \"\",\"comment\": \"this is my comment\"}";

            debug(input);
            os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            //409 response code means there is an existing card template on the user
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            sb = new StringBuilder();

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            json = new JSONObject(sb.toString());

            conn.disconnect();
            msg = json.getString("auth_t_id");
            debug("Response: " + msg);

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }

        return null;
    }

    public static String doPasswordEnroll(String password, String loginSessionId, String targetUserID)
    {

        try
        {
            URL url = new URL(targetURL + "/api/v1/enroll");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"method_id\": \"PASSWORD:1\",\"login_session_id\":\"" + loginSessionId + "\"}";

            debug(input);
            OutputStream os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
            String enroll_process_id = json.getString("enroll_process_id");
            debug(enroll_process_id);

            url = new URL(targetURL + "/api/v1/enroll/" + enroll_process_id + "/do_enroll");
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            input = "{\"response\": {\"password\": \"" + password + "\"},\"login_session_id\": \"" + loginSessionId + "\"}";

            debug(input);
            os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            sb = new StringBuilder();

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            json = new JSONObject(sb.toString());

            conn.disconnect();
            String status = json.getString("status");
            String msg = json.getString("msg");
            debug("Response: " + status + " : " + msg);

            url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates");
            debug(url.toString());
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            input = "{\"login_session_id\": \"" + loginSessionId + "\",\"enroll_process_id\": \"" + enroll_process_id + "\",\"category_id\": \"\",\"comment\": \"this is my comment\"}";

            debug(input);
            os = conn.getOutputStream();
            os.write(input.getBytes());
            os.flush();

            //409 response code means there is an existing card template on the user
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            sb = new StringBuilder();

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            json = new JSONObject(sb.toString());

            conn.disconnect();
            msg = json.getString("auth_t_id");
            debug("Response: " + msg);

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }

        return null;
    }

    public static String getTargetUserId(String targetUserID, String loginSessionId)
    {

        try
        {

            URL url = new URL(targetURL + "/api/v1/users?user_name=" + targetUserID + "&login_session_id=" + loginSessionId);
            debug(url.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND)
            {
                return null;
            }

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());

            JSONObject json = new JSONObject(sb.toString());
            debug(json.toString());
            conn.disconnect();

            String id = json.getString("id");
            debug(id);
            return id;

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }
        return null;
    }

    public static String unlinkTemplate(String targetUserID, String loginSessionId, String templateID)
    {

        try
        {

            URL url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates/" + templateID + "?login_session_id=" + loginSessionId);
            debug(url.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("DELETE");

            if (conn.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND)
            {
                return null;
            }

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }
        return null;
    }

    public static String checkExistingCard(String targetUserID, String loginSessionId)
    {

        try
        {

            URL url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates?login_session_id=" + loginSessionId);
            debug(url.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());
            JSONObject json = new JSONObject(sb.toString());
            debug(json.toString());
            conn.disconnect();

            JSONArray templates = json.getJSONArray("templates");
            Iterator myIter = templates.iterator();
            String id = "";
            while (myIter.hasNext())
            {
                JSONObject template = (JSONObject) myIter.next();
                String method_id = template.getString("method_id");
                debug(method_id);
                if (method_id.equals("CARD:1"))
                {
                    id = template.getString("id");
                    debug("existing card found: " + id);

                }
            }

            return id;

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }
        return null;
    }

    public static String checkExistingPassword(String targetUserID, String loginSessionId)
    {

        try
        {

            URL url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates?login_session_id=" + loginSessionId);
            debug(url.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            debug("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            debug(sb.toString());
            JSONObject json = new JSONObject(sb.toString());
            debug(json.toString());
            conn.disconnect();

            JSONArray templates = json.getJSONArray("templates");
            Iterator myIter = templates.iterator();
            String id = "";
            while (myIter.hasNext())
            {
                JSONObject template = (JSONObject) myIter.next();
                String method_id = template.getString("method_id");
                debug(method_id);
                if (method_id.equals("PASSWORD:1"))
                {
                    id = template.getString("id");
                    debug("existing PASSWORD found: " + id);

                }
            }

            return id;

        }
        catch (MalformedURLException e)
        {

            e.printStackTrace();

        }
        catch (IOException e)
        {

            e.printStackTrace();

        }
        return null;
    }

    private static void debug(String logEntry)
    {
        if (debug.equalsIgnoreCase("true"))
        {
            System.out.println(logEntry);

        }
    }

    private static void logToFile(String logEntry) throws IOException
    {
        System.out.println(logEntry);
        logFile.write(logEntry + "\n");

    }

    private static String encodeCardID(String siteNumber, String cardNumber)
    {
        //0000000000B82FEE

        String siteHex = Integer.toHexString(Integer.parseInt(siteNumber));
        String cardHex = Integer.toHexString(Integer.parseInt(cardNumber));

        String siteCardHex = "0000000000000000".substring(0, 16 - (siteHex.length() + cardHex.length())) + siteHex + cardHex;

        return siteCardHex;

    }
}
