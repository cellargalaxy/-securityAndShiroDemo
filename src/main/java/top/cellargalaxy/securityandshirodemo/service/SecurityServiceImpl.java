package top.cellargalaxy.securityandshirodemo.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;
import top.cellargalaxy.securityandshirodemo.model.SecurityUser;

import java.util.*;

/**
 * @author cellargalaxy
 * @time 2018/7/31
 */
@Service
public class SecurityServiceImpl implements SecurityService {
	private final String secret = "secret";
	public static final int EXPIRATION_TIME = 1000 * 60 * 60 * 6;
	public static final String AUTHORITIE_KEY = "authorities";

	@Override
	public SecurityUser getSecurityUser(String username) {
		if ("root".equals(username)) {
			return new SecurityUserImpl("root", "123456") {{
				getPermissions().add("USER");
				getPermissions().add("ROLE_ROOT");
			}};
		}
		return null;
	}

	@Override
	public String login(String username) {
		SecurityUser securityUser = getSecurityUser(username);
		if (securityUser == null) {
			return null;
		}
		//获取账号的权限，然后变成用逗号相间隔的字符串
		StringBuilder stringBuilder = new StringBuilder();
		Iterator<String> iterator = securityUser.getPermissions().iterator();
		if (iterator.hasNext()) {
			stringBuilder.append(iterator.next());
		}
		while (iterator.hasNext()) {
			stringBuilder.append("," + iterator.next());
		}

		String jwt = Jwts.builder()
				//保存权限/角色
				.claim(AUTHORITIE_KEY, stringBuilder.toString())
				//用户名写入标题
				.setSubject(username)
				//有效期设置
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				//签名设置
				.signWith(SignatureAlgorithm.HS512, secret)
				.compact();
		return jwt;
	}

	@Override
	public SecurityUser checkToken(String token) {
		if (token == null) {
			return null;
		}
		try {
			Claims claims = Jwts.parser()
					.setSigningKey(secret)
					.parseClaimsJws(token)
					.getBody();
			String username = claims.getSubject();
			final String[] permissions = claims.get(AUTHORITIE_KEY, String.class).split(",");
			return new SecurityUserImpl(username, null) {{
				for (String permission : permissions) {
					getPermissions().add(permission);
				}
			}};
		} catch (Exception e) {
			System.out.println("token解析失败：" + e);
		}
		return null;
	}

	class SecurityUserImpl implements SecurityUser {
		private final String username;
		private final String password;
		private final Set<String> permissions;

		public SecurityUserImpl(String username, String password) {
			this.username = username;
			this.password = password;
			permissions = new HashSet<>();
		}

		@Override
		public String getUsername() {
			return username;
		}

		@Override
		public String getPassword() {
			return password;
		}

		@Override
		public Set<String> getPermissions() {
			return permissions;
		}

		@Override
		public String toString() {
			return "SecurityUserImpl{" +
					"username='" + username + '\'' +
					", password='" + password + '\'' +
					", permissions=" + permissions +
					'}';
		}
	}
}
