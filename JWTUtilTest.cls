@isTest
public class JWTUtilTest {
    @isTest
    public static void authTest(){
        JWTUtil.UserInfo existUser = new JWTUtil.UserInfo();
        existUser.email = 'test@email.com';
        existUser.password = 'Password';
        String token = JWTUtil.createToken(existUser);
        
        System.assertNotEquals(null, token);
        
        JWTUtil.UserInfo notExistUser = new JWTUtil.UserInfo();
        notExistUser.email = 'test1@email.com';
        notExistUser.password = 'Password';
        String nullToken = JWTUtil.createToken(notExistUser);
        
        System.assertEquals(null, nullToken);
        
        System.assertEquals(true, JWTUtil.auth(token));
        System.assertEquals(false, JWTUtil.auth('nullToken'));
        
        JWTUtil.Payload payload = JWTUtil.getUserInfo(token);
        JWTUtil.InMemoryUser memoryUser = JWTUtil.inMemoryUserMap.get(payload.name);
        System.assertEquals(memoryUser.userId, payload.sub);
    }
}