public class JWTUtil {
    private static String secretKey;
    private static String algorithm;
    private static String security;
    @TestVisible
    private static Map<String,InMemoryUser> inMemoryUserMap;
    
    static{
        secretKey = '1234567890qwertyuiop[]asdfghjkl;zxcvbnm,./===-_)+(*&^%$##@!';
        algorithm = 'HmacSHA256';
        security = 'JWT';
        inMemoryUserMap = new Map<String,InMemoryUser>();
        inMemoryUserMap.put('test@email.com', new InMemoryUser('123','test@email.com','Password'));
    }
    
    private static InMemoryUser getInMemoryUser(UserInfo user){
        InMemoryUser selectedUser = inMemoryUserMap.get(user.email);
        if(selectedUser==null){
            return null;
        }
        if(selectedUser.password!=user.password){
            return null;
        }
        return selectedUser;
    }
    
    private static Boolean isInMemoryUserExist(String email){
        if(inMemoryUserMap.get(email)!=null){
            return true;
        }
        return false;
    }
	
    public static String createToken(UserInfo user){
        if(user!=null){
            Header header = new Header();
            header.alg = algorithm;
            header.typ = security;
            InMemoryUser selectedUser = getInMemoryUser(user);
            Payload payload = new Payload();
            if(selectedUser==null){
                return null;
            }
            payload.sub = selectedUser.userId;
            payload.name = selectedUser.email;
            payload.admin = false;
            String headerAndPayload = EncodingUtil.base64Encode(Blob.valueOf(JSON.serialize(header)))+'.'+EncodingUtil.base64Encode(Blob.valueOf(JSON.serialize(payload)));
            String signature = EncodingUtil.base64Encode(Crypto.generateMac(algorithm, Blob.valueOf(headerAndPayload), Blob.valueOf(secretKey)));
            String token = headerAndPayload+'.'+signature;
            return token;
        }
        return null;
    }
    
    public static Boolean auth(String token){
        if(token!=null){
            String[] auth = token.split('\\.');
            if(auth.size()==3){
                Blob headerBlob = EncodingUtil.base64Decode(auth[0]);
                Blob payloadBlob = EncodingUtil.base64Decode(auth[1]);
                String hmac = auth[2];
                JWTUtil.Header header = (JWTUtil.Header) JSON.deserialize(headerBlob.toString(), JWTUtil.Header.class);
                JWTUtil.Payload payload = (JWTUtil.Payload) JSON.deserialize(payloadBlob.toString(), JWTUtil.Payload.class);
                if(isInMemoryUserExist(payload.name)){
                    String newHmac = EncodingUtil.base64Encode(Crypto.generateMac(header.alg, Blob.valueOf(auth[0]+'.'+auth[1]), Blob.valueOf(secretKey)));
                    if(hmac==newHmac){
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    public static Payload getUserInfo(String token){
        if(token!=null){
            String[] auth = token.split('\\.');
            if(auth.size()==3){
                Blob payloadBlob = EncodingUtil.base64Decode(auth[1]);
                JWTUtil.Payload payload = (JWTUtil.Payload) JSON.deserialize(payloadBlob.toString(), JWTUtil.Payload.class);
                return payload;
            }
        }
        return null;
    }
        
    public class Header{
        public String alg;
        public String typ;
    }
    
    public class Payload{
    	public String sub;
        public String name;
        public Boolean admin;
    }
    
    public class UserInfo{
        public String email;
        public String password;
    }
    
    @TestVisible
    private class InMemoryUser{
        public String userId;
        public String email;
        public String password;
        
        public InMemoryUser(String userId, String email, String password){
            this.userId = userId;
            this.email = email;
            this.password = password;
        }
    }
}