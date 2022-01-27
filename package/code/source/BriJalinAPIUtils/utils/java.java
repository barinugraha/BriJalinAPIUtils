package BriJalinAPIUtils.utils;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wm.app.b2b.server.jaxrpc.MessageContext;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataUtil;
import com.wm.passman.PasswordManagerException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import com.wm.app.b2b.server.globalvariables.GlobalVariablesException;
import com.wm.app.b2b.server.globalvariables.GlobalVariablesManager;
import com.wm.util.GlobalVariables;
import com.wm.util.GlobalVariables.GlobalVariableValue;
// --- <<IS-END-IMPORTS>> ---

public final class java

{
	// ---( internal utility methods )---

	final static java _instance = new java();

	static java _newInstance() { return new java(); }

	static java _cast(Object o) { return (java)o; }

	// ---( server methods )---




	public static final void CreateOAuthSignature (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(CreateOAuthSignature)>> ---
		// @sigtype java 3.5
		// [i] object:0:required privateKey
		// [i] field:0:required timestampRequest
		// [i] field:0:required clientId
		// [o] field:0:required signature
		// pipeline
		IDataCursor pipelineCursor = pipeline.getCursor();
		String JAVA_SERVICE = "[CreateOAuthSignature] ";
		//populate required data
		RSAPrivateKey privateKey = (RSAPrivateKey) IDataUtil.get(pipelineCursor, "privateKey");
		String timestampRequest = IDataUtil.getString( pipelineCursor, "timestampRequest" );
		String clientId = IDataUtil.getString( pipelineCursor, "clientId" );
		
		logMessageToServerLog(pipeline, JAVA_SERVICE + "timestampRequest = " + timestampRequest);
		logMessageToServerLog(pipeline, JAVA_SERVICE + "clientId = " + clientId);
		
		pipelineCursor.destroy();
		
		String data = clientId+"|"+timestampRequest;
		logMessageToServerLog(pipeline, JAVA_SERVICE + "data = " + data);
		
		String signature = "";
		
		try {
			
			//create signature
			signature = sign(privateKey, data);
			logMessageToServerLog(pipeline, JAVA_SERVICE + "signature = " + signature);
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
		IDataCursor pipelineCursorOut = pipeline.getCursor();
		IDataUtil.put( pipelineCursorOut, "signature", signature );
		pipelineCursorOut.destroy();
		// --- <<IS-END>> ---

                
	}



	public static final void ExceptionHandling (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(ExceptionHandling)>> ---
		// @sigtype java 3.5
		// [i] field:0:required payload
		// [o] object:0:required statusCode
		// [o] field:0:required statusMessage
		IDataCursor pipelineCursor = pipeline.getCursor();
		String JAVA_SERVICE = "[ExceptionHandling] ";
		String payload = IDataUtil.getString(pipelineCursor, "payload");
		logMessageToServerLog(pipeline, JAVA_SERVICE + "payload = " + payload);
		pipelineCursor.destroy();
				
		IDataCursor pipelineCursorOut = pipeline.getCursor();
		IDataUtil.put( pipelineCursorOut, "statusCode", Integer.parseInt(payload.split("#")[1]));
		IDataUtil.put( pipelineCursorOut, "statusMessage", payload.split("#")[2]);
		pipelineCursorOut.destroy();
		// --- <<IS-END>> ---

                
	}



	public static final void HmacSha512 (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(HmacSha512)>> ---
		// @sigtype java 3.5
		// [i] field:0:required secretKey
		// [i] field:0:required timestampRequest
		// [i] field:0:required bodyRequest
		// [i] field:0:required resourceUrl
		// [i] field:0:required httpMethod
		// [i] field:0:required accessToken
		// [o] field:0:required encodedData
		// pipeline
		IDataCursor pipelineCursor = pipeline.getCursor();
		String JAVA_SERVICE = "[HmacSha512] ";
		String	secretKey = IDataUtil.getString( pipelineCursor, "secretKey" );
		String	bodyRequest = IDataUtil.getString( pipelineCursor, "bodyRequest" );
		String	httpMethod = IDataUtil.getString( pipelineCursor, "httpMethod" );
		String	resourceUrl = IDataUtil.getString( pipelineCursor, "resourceUrl" );
		String	accessToken = IDataUtil.getString( pipelineCursor, "accessToken" );
		String	timestampRequest = IDataUtil.getString( pipelineCursor, "timestampRequest" );
		
		String data = "";
		logMessageToServerLog(pipeline, JAVA_SERVICE + "secretKey = ***");
		logMessageToServerLog(pipeline, JAVA_SERVICE + "bodyRequest = " + bodyRequest);
		logMessageToServerLog(pipeline, JAVA_SERVICE + "httpMethod = " + httpMethod);
		logMessageToServerLog(pipeline, JAVA_SERVICE + "resourceUrl = " + resourceUrl);
		logMessageToServerLog(pipeline, JAVA_SERVICE + "accessToken = " + accessToken);
		logMessageToServerLog(pipeline, JAVA_SERVICE + "timestampRequest = " + timestampRequest);
		
		if(bodyRequest == null || bodyRequest == ""){			
			data = httpMethod+":"+resourceUrl+":"+accessToken +":"+""+":"+timestampRequest;			
		} else {			
			ObjectMapper objectMapper = new ObjectMapper();
		    try {
				JsonNode jsonNode = objectMapper.readValue(bodyRequest, JsonNode.class);
				bodyRequest = jsonNode.toString();
			} catch (Exception e) {
				e.printStackTrace();
				logMessageToServerLog(pipeline, JAVA_SERVICE + "Exception = " + e.getMessage(), null, "error");
				bodyRequest = "";
			} 
			data = httpMethod+":"+resourceUrl+":"+accessToken+":"+bodyRequest+":"+timestampRequest;			
		}
		logMessageToServerLog(pipeline, JAVA_SERVICE + "Data to be encoded = " + data);
					
		try {
			SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes(), SHA512ALGORITHM);
			Mac mac = Mac.getInstance(SHA512ALGORITHM);
			mac.init(signingKey);
			char[] resultHex = Hex.encodeHex(mac.doFinal(data.getBytes()));
		    String encodedData = new String(resultHex);
		    if(encodedData!=null)
		    	encodedData = encodedData.toUpperCase();
			IDataUtil.put( pipelineCursor, "encodedData", encodedData );
			pipelineCursor.destroy();
		
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			((Throwable) e).printStackTrace();
		}
		// --- <<IS-END>> ---

                
	}



	public static final void ValidateOAuthSignature (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(ValidateOAuthSignature)>> ---
		// @sigtype java 3.5
		// [i] object:1:required certChain
		// [i] field:0:required signature
		// [i] field:0:required himbaraKey
		// [i] field:0:required timestamp
		// [i] field:0:required payload
		// [o] field:0:required isVerified
		// [o] field:0:required outMessage
		// [o] field:0:required httpCode
		String isVerified = "false";
		String outMessage = "";
		String JAVA_SERVICE = "[ValidateOAuthSignature] ";
		try{			
			//populate input
			IDataCursor pipelineCursor = pipeline.getCursor();
			byte[][] certChain = (byte[][])IDataUtil.getObjectArray(pipelineCursor, "certChain");
			String signature = IDataUtil.getString(pipelineCursor, "signature");
			String himbaraKey = IDataUtil.getString(pipelineCursor, "himbaraKey");
			String timestamp = IDataUtil.getString(pipelineCursor, "timestamp");
			String payload = IDataUtil.getString(pipelineCursor, "payload");
			
			logMessageToServerLog(pipeline, JAVA_SERVICE+" signature = " + signature + ", himbaraKey = " + himbaraKey+",timestamp = " + timestamp+",payload = " + payload);
			
			pipelineCursor.destroy();
			
			//validate grant type
			if(payload==null || payload.equals("")){
				isVerified = "false";
				outMessage = "400#Bad Request";
			}else{
				boolean grantTypeFound = false;
				String[] params = payload.split("&");
				for (String param : params) {
					String[] keyval = param.split("=");
					if("grant_type".equals(keyval[0])){
						grantTypeFound = true;
						if("client_credentials".equals(keyval[1])){
							isVerified = "true";
							outMessage = "200#Success";
						} else{
							isVerified = "false";
							outMessage = "400#Unsupported grant_type";
						}
						break;
					}
				}
				if(!grantTypeFound){
					isVerified = "true";
					outMessage = "400#Bad Request";
				}
			}			
			if("true".equals(isVerified)){
				logMessageToServerLog(pipeline, JAVA_SERVICE + "checking signature"); 
				//data to be validated			
				String data = himbaraKey+"|"+timestamp;
				byte[] byteData = data.getBytes("UTF-8");
				
				//get public key from chain
				logMessageToServerLog(pipeline, JAVA_SERVICE + "get public key from chain");
				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(certChain[0]);
				Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
				PublicKey pubKey = cert.getPublicKey();
				
				//verify signature
				logMessageToServerLog(pipeline, JAVA_SERVICE + "start verify signature");
				Signature signn = Signature.getInstance("SHA256withRSA");
				byte[] byteSignature = Base64.getDecoder().decode(signature);
				signn.initVerify(pubKey);
				signn.update(byteData);
				Boolean verified = signn.verify(byteSignature);
				logMessageToServerLog(pipeline, JAVA_SERVICE + "end verify signature verified = "+verified);
				
				if(verified){
					isVerified = "true";
					outMessage = "200#Success";
				}else{
					isVerified = "false";
					outMessage = "401#Unauthorized";
				}
			}			
		}catch (Exception e) {
			e.printStackTrace();
			logMessageToServerLog(pipeline, JAVA_SERVICE + "error = " + e.getMessage());
			isVerified = "false";
			outMessage = "401#Unauthorized";
		}finally {
			IDataCursor pipelineCursorOut = pipeline.getCursor();
			IDataUtil.put( pipelineCursorOut, "isVerified", isVerified );
			IDataUtil.put( pipelineCursorOut, "outMessage", outMessage );			
			pipelineCursorOut.destroy();
			
			logMessageToServerLog(pipeline, JAVA_SERVICE + "isVerified = " + isVerified + ", outMessage = " + outMessage);			
		}
		// --- <<IS-END>> ---

                
	}

	// --- <<IS-START-SHARED>> ---
	
	private static final String SHA512ALGORITHM = "HmacSHA512";
	
	public static String sign(RSAPrivateKey privateKey, String data) {
		
		String signature = null;
	
		try {
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privateKey);
			byte[] byteMessage = data.getBytes();
	
			sign.update(byteMessage, 0, byteMessage.length);
			byte[] byteSignature = sign.sign();
	
			signature = new String(Base64.getEncoder().encode(byteSignature));
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return signature;
	}
	
	public static void logMessageToServerLog(
			IData pipeline, 
		    String message) throws ServiceException{
		logMessageToServerLog(pipeline,"[BriJalinAPIUtils]"+message,null,null);
	}
	
	public static void logMessageToServerLog(
		    IData pipeline, 
		    String message, 
		    String function, 
		    String level) 
		    throws ServiceException 
		{ 
		    IDataCursor inputCursor = pipeline.getCursor(); 
		    IDataUtil.put(inputCursor, "message", message); 
		    IDataUtil.put(inputCursor, "function", function); 
		    IDataUtil.put(inputCursor, "level", level); 
		    inputCursor.destroy(); 
	
		    try
		    {
		        Service.doInvoke("pub.flow", "debugLog", pipeline);
		    }
		    catch (Exception e)
		    {
		        throw new ServiceException(e.getMessage());
		    }
		}
		
	// --- <<IS-END-SHARED>> ---
}

