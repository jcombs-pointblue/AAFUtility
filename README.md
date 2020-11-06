# AAFUtility
Advanced Authentication Card Utility

Micro Focus Advanced Authentication provides a REST API that is used by this utility to register authentication cards and associate them with users.

The utility is implemented in Java and require JRE 1.8 or higher. The components of the utility are:
•	dist/AAFUtility.jar – contain the utility
•	/lib/commons-codec-1.11.jar – The Apache codec library
•	/lib/json-20180813.jar – The org.json library
•	AAFUtility.properties – The properties file used to configure the utility.

The utility requires a CSV file as input. The format of the file is:

Repository\userID,site ID,cardID,password
For example:

LOCAL\admin,184,271212,password01

If all the users are in a single repository then you may omit the “Repository\” if you specify the userRepository property in the properties file. Note that you must include two slashes after the repository name in the properties file.

Before the utility can be used you must create an Endpoint definition for the REST API. This is done in the AAF Admin interface.

1.	Select Endpoints
2.	Select Add
