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

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception
    {
        init(args);
        //repository
        //String username = "LOCAL\\admin";
        //String cardUID = "0e62f260aa610be177ba6c5d052ef003"; //0e62f260aa610be177ba6c5d052ef002

        String secretHash = getEndpointSecretHash(endPointID, endPointSecret);
        System.out.println(secretHash);
        trustAllHosts();
        String epSessionId = getEndPointSessionId(endPointID, secretHash);
        String logonProcessId = getLoginSession(epSessionId, adminID);
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
                
                String targetUserId = userRepository + fields[0];
                //Note single slash instead of double needed for using it in json as above
                String id = getTargetUserId(targetUserId, loginSessionId);
                //Check for bad ID
                if(id == null || id.equals(""))
                {
                    logToFile(targetUserId + " :Enrollment Failed: User Not Found");
                    continue;
                }
                String existingCardID = checkExistingCard(id, loginSessionId);
                
                if (existingCardID.equals(""))
                {
                    //debug("No existing card found, adding card");
                    String response = doCardEnroll(fields[1], loginSessionId, id);
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
                        logToFile(targetUserId  + " :Existing card found, you must delete the existing card first");

                    }
                    if (mode.equals("update"))
                    {
                        //remove template
                        unlinkTemplate(id,loginSessionId, existingCardID);

                        //add template
                        String response = doCardEnroll(fields[1], loginSessionId, id);
                        if (response != null)
                        {
                            logToFile(targetUserId  + " :Enrollment Failed");
                        }
                        else
                        {
                            logToFile(targetUserId  + " :Enrollment Succeeded");
                        }

                    }
                    if (mode.equals("clear"))
                    {
                        //remove template
                          //remove template
                        unlinkTemplate(id,loginSessionId, existingCardID);
                        logToFile(targetUserId  + " :Deleted Card");
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
            adminPW = args[2];
            mode = props.getProperty("mode"); //add,update,clear
            dataFile = args[1];
            targetURL = props.getProperty("targetURL");
            userRepository = props.getProperty("userRepository");

        }
        else
        {
            System.out.println("please specify config file path, a path to data file, and password");
            System.exit(-1);

        }

        /*   endPointID = "d5361e8ae79c11e8aaea0242ac120002";
        endPointSecret = "arw1IYp7snnx50DgZ5ZavntRLiLZdZzo";
        adminID = "\"LOCAL\\\\admin\"";
        adminPW = "dittibop";
        mode = "add"; //add,update,clear
        targetURL = "https://aaf61.pointbluetech.com";
         */
    }

    //Endpoint ID d5361e8ae79c11e8aaea0242ac120002
    //End Point Secret arw1IYp7snnx50DgZ5ZavntRLiLZdZzo
    /* Python code for hash
    def get_endpoint_secret_hash(endpoint, salt): # Calculates endpoint secret hash as SHA256(endpoint.secret, SHA256(endpoint.id_hex + salt)) # salt is random string of length >= 1
    
    salted_endpoint_id = (endpoint.id_hex + salt).encode('utf-8')
        endpoint_id_hash = sha256(salted_endpoint_id).hexdigest()
        salted_enpoint_secret = (endpoint.secret + endpoint_id_hash).encode('utf-8')

        return sha256(salted_enpoint_secret).hexdigest()
    
    POST to /api/v1/endpoints/{endpoint_id}/sessions  returns session ID
    salted hash posted as endpoint_id
     */
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

        try
        {

            URL url = new URL(targetURL + "/api/v1/endpoints/" + id + "/sessions");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"salt\": \"randomSalt\",\"endpoint_secret_hash\": \"" + secret + "\",\"session_data\":{\"any\": { \"data\": [\"you\", \"want to store\", \"in session\"] }}}";

            //String input = "{\"endpoint_id\":\"" + secret + "\"}";
            System.out.println(input);
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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to getid from JSON
            // {"endpoint_session_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();

            String endpoint_session_id = json.getString("endpoint_session_id");
            System.out.println(endpoint_session_id);
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
        return null;
    }

    public static String getLoginSession(String epSessionId, String userID)
    {

        //get user methods
        // If we use admin we can assume password
        //Start logon process
        /*
        POST /api/v1/logon
    {
        {
  "method_id": "PASSWORD:1",
  "user_name": "LOCAL\\USER1",
  "event": "NAM",
  "endpoint_session_id": "P7p3JJuenqo0SnyJ4HnbRbbJIqDhtt0u"
}
    }
         */
        try
        {

            URL url = new URL(targetURL + "/api/v1/logon");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
//"name":"Authenticators Management","id":"e5412a88dc6e11e8b4740242ac120002"
            //String input = "{\"method_id\": \"PASSWORD:1\",\"user_name\": " + userID + ",\"event\": \"Authenticators Management\",\"endpoint_session_id\": \"" + epSessionId + "\"}";
            String input = "{\"method_id\": \"PASSWORD:1\",\"user_name\": " + userID + ",\"event\": \"Helpdesk\",\"endpoint_session_id\": \"" + epSessionId + "\"}";

            //String input = "{\"endpoint_id\":\"" + secret + "\"}";
            System.out.println(input);
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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to get id from JSON
            // {"logon_process_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
            String logon_process_id = json.getString("logon_process_id");
            System.out.println(logon_process_id);
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

        /*    
        
        Grab logon_process_id and perform series of do_logon calls while getting status ‘MORE_DATA’::    
        
        //doLogon
        POST /api/v1/logon/Ww323YxvYv6IVj3J3EaLNlkVM2aoHfLa/do_logon
    {
        "response": "method-specific dictionary, maybe omitted if method does not requires data on 1st do_login"
    }

Return
    {
        # method-specific data such as
        "challenge": {"rounds": 100, "salt": "cdf123Dx"},
        "status": "MORE_DATA"
    }
        
     POST /api/v1/logon/Ww323YxvYv6IVj3J3EaLNlkVM2aoHfLa/do_logon
    {
        "response": {"answer" : "my-password" # method-specific dict in "response" field}
                                              # this is "response" to "challenge" which server sent in previous do_logon
    }   
        
         */
        return null;//logonSessionId;    

    }

    public static String doLogin(String epSessionId, String logonProcessId, String password)
    {
        /*    
        
        
     POST /api/v1/logon/Ww323YxvYv6IVj3J3EaLNlkVM2aoHfLa/do_logon
    ---For PASSWORD:1----
        {
  "endpoint_session_id": "P7p3JJuenqo0SnyJ4HnbRbbJIqDhtt0u",
  "response": {
    "answer": "my-password"
  }
}
        
         */

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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to get id from JSON
            // {"logon_process_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
            String login_session_id = json.getString("login_session_id");
            System.out.println(login_session_id);
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

        return null;

    }

    public static String doCardEnroll(String cardUID, String loginSessionId, String targetUserID)
    {
        // /api/v1/enroll
        /*
        
        {
    "method_id": "HOTP:1",
    //login method to create authentication template for
    "login_session_id":"B3XBHzwAHuPfHwMHfSjf3eVdV3glCa0o"
}
        
     
         */
        try
        {
            URL url = new URL(targetURL + "/api/v1/enroll");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            String input = "{\"method_id\": \"CARD:1\",\"login_session_id\":\"" + loginSessionId + "\"}";

            System.out.println(input);
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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to get id from JSON
            // {"logon_process_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());

            conn.disconnect();
            String enroll_process_id = json.getString("enroll_process_id");
            System.out.println(enroll_process_id);

            // /api/v1/enroll/{enroll_process_id}/do_enroll
            url = new URL(targetURL + "/api/v1/enroll/" + enroll_process_id + "/do_enroll");
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            /*
            {"response": {"card_cert": "308205243082040ca00302010202100e62f26..................a5883aa073b4588","card_uid": "0e62f260aa610be177ba6c5d052ef002"},"login_session_id": "KOYxcRUuuZxDsEhxiycof4XwcuI2lbwk"}
            
             */
            // /api/v1/enroll/{enroll_process_id}/do_enroll
            /*
        {
             "response": {
             "card_cert": "308205243082040ca00302010202100e62f26..................a5883aa073b4588",
             "card_uid": "0e62f260aa610be177ba6c5d052ef002"},"login_session_id": "KOYxcRUuuZxDsEhxiycof4XwcuI2lbwk"}
            
             */
            input = "{\"response\": {\"card_cert\": \"\",\"card_uid\": \"" + cardUID + "\"},\"login_session_id\": \"" + loginSessionId + "\"}";

            System.out.println(input);
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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to get id from JSON
            // {"logon_process_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            json = new JSONObject(sb.toString());

            conn.disconnect();
            String status = json.getString("status");
            String msg = json.getString("msg");
            System.out.println("Response: " + status + " : " + msg);

            //create template, fill it from enroll, and link to user
            // /api/v1/users/{user_id}/templates
            /*
        {"login_session_id": "LRvql8GD946V7ryN8fesWBLhN1I7dpEe","enroll_process_id": "rlV6pSKXT4e0Ueq9hEXreL1ubkAdNYz2","category_id": "hex or empty","comment": "this is my comment"}
             */
            url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates");
            System.out.println(url);
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            input = "{\"login_session_id\": \"" + loginSessionId + "\",\"enroll_process_id\": \"" + enroll_process_id + "\",\"category_id\": \"\",\"comment\": \"this is my comment\"}";

            System.out.println(input);
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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to get id from JSON
            // {"logon_process_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            json = new JSONObject(sb.toString());

            conn.disconnect();
            msg = json.getString("auth_t_id");
            System.out.println("Response: " + msg);

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
            /*
            GET /api/v1/users?user_name=LOCAL\ADMIN&login_session_id=JHAHdZiRKdaYcPhQUHcPYgYSElFcMBVX

            -----------
            response
                    {
      "obj_id": "3caa08a0061e11e6b224080027983191",
      "user_name": "LOCAL\ADMIN",
      "last_fail_at": null,
      "repo_id": "3c9c1fd8061e11e6b224080027983191",
      "repo_name": "LOCAL",
      "id": "4f34e2882991440ddd0fd515e0d0236c",
      "loginame": "ADMIN"
    }
             */
            //URL url = new URL("https://aaf61.pointbluetech.com/api/v1/events?login_session_id="+loginSessionId);                    
            URL url = new URL(targetURL + "/api/v1/users?user_name=" + targetUserID + "&login_session_id=" + loginSessionId);
            System.out.println(url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");
            //conn.setRequestProperty("Content-Type", "application/json");

            //String input = "{\"salt\": \"randomSalt\",\"endpoint_secret_hash\": \"" + secret + "\",\"session_data\":{\"any\": { \"data\": [\"you\", \"want to store\", \"in session\"] }}}";
            //String input = "{\"endpoint_id\":\"" + secret + "\"}";
            //System.out.println(input);
            //OutputStream os = conn.getOutputStream();
            //os.write(input.getBytes());
            //.flush();
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

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to getid from JSON
            // {"endpoint_session_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());
            System.out.println(json.toString());
            conn.disconnect();

            String id = json.getString("id");
            System.out.println(id);
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
          
             //DELETE /api/v1/users/4f34e2882991440ddd0fd515e0d0236c/templates/83523194b70919672b1157bc929ed67a?login_session_id=JHAHdZiRKdaYcPhQUHcPYgYSElFcMBVX
            URL url = new URL(targetURL + "/api/v1/users/" + targetUserID +"/templates/"+templateID+ "?login_session_id=" + loginSessionId);
            System.out.println(url);
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

            System.out.println("Output from Server .... \n");
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
            /*
            GET /api/v1/users/4f34e2882991440ddd0fd515e0d0236c/templates?login_session_id=JHAHdZiRKdaYcPhQUHcPYgYSElFcMBVX
            
            {
  "templates": [
    {
      "id": "3cb97b50061e11e6b224080027983191",
      "method_id": "PASSWORD:1",
      "method_title": "Password",
      "is_enrolled": true,
      "comment": ""
    },
    {
      "id": "83523194b70919672b1157bc929ed67a",
      "method_id": "CARD:1",
      "method_title": "Card",
      "is_enrolled": true,
      "comment": ""
    },
    {
      "id": "ff3f4e84203e6d7f56a0013074237071",
      "method_id": "SECQUEST:1",
      "method_title": "Security Questions",
      "is_enrolled": true,
      "comment": ""
    },
    {
      "id": "5194c010d968811da4ff47f843a3245e",
      "method_id": "HOTP:1",
      "method_title": "HOTP",
      "is_enrolled": true,
      "comment": ""
    }
  ]
}
            
             */
            URL url = new URL(targetURL + "/api/v1/users/" + targetUserID + "/templates?login_session_id=" + loginSessionId);
            System.out.println(url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");
            //conn.setRequestProperty("Content-Type", "application/json");

            //String input = "{\"salt\": \"randomSalt\",\"endpoint_secret_hash\": \"" + secret + "\",\"session_data\":{\"any\": { \"data\": [\"you\", \"want to store\", \"in session\"] }}}";
            //String input = "{\"endpoint_id\":\"" + secret + "\"}";
            //System.out.println(input);
            //OutputStream os = conn.getOutputStream();
            //os.write(input.getBytes());
            //.flush();
            
           
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
            }
            

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));

            StringBuilder sb = new StringBuilder();

            String output;

            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null)
            {
                sb.append(output);

            }
            System.out.println(sb.toString());
            //need to getid from JSON
            // {"endpoint_session_id": "2W1zeGXbtO29Cps0wpEeotVfd9iqqod4"}
            JSONObject json = new JSONObject(sb.toString());
            System.out.println(json.toString());
            conn.disconnect();

            JSONArray templates = json.getJSONArray("templates");
            Iterator myIter = templates.iterator();
            String id = "";
            while (myIter.hasNext())
            {
                JSONObject template = (JSONObject) myIter.next();
                String method_id = template.getString("method_id");
                //System.out.println(method_id);
                if (method_id.equals("CARD:1"))
                {
                    id = template.getString("id");
                    //System.out.println("existing card found: " + id);

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
        System.out.println(logEntry);
    }

    private static void logToFile(String logEntry) throws IOException
    {
        System.out.println(logEntry);
        logFile.write(logEntry + "\n");

    }
}
