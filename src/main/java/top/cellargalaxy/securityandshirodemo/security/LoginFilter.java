package top.cellargalaxy.securityandshirodemo.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import top.cellargalaxy.securityandshirodemo.service.SecurityService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * @author cellargalaxy
 * @time 2018/7/30
 */
public class LoginFilter extends AbstractAuthenticationProcessingFilter {
	public static final String USERNAME_KEY = "username";
	public static final String PASSWORD_KEY = "password";
	public static final String TOKEN_KEY = "Authorization";
	private final SecurityService securityService;
	private final ObjectMapper objectMapper;

	public LoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager, SecurityService securityService) {
		//下面两行不知道啥意思，可能是配置这个Filter的路径之类的吧
		super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
		setAuthenticationManager(authenticationManager);
		this.securityService = securityService;
		objectMapper = new ObjectMapper();
	}

	//在检验账号密码前会调用，用于自定义获取账号密码
	@Override
	public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
		httpServletResponse.setCharacterEncoding("utf-8");
		String username = httpServletRequest.getParameter(USERNAME_KEY);
		String password = httpServletRequest.getParameter(PASSWORD_KEY);
		System.out.println("检验登录,username: " + username);
		//返回这个对象，封装了账号密码，用于给框架检查账号密码是否正确
		return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password));
	}

	//如果账号密码正确会调用这个方法
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		String username = request.getParameter(USERNAME_KEY);
		String token = securityService.createToken(username);

		System.out.println("登录成功,username: " + username + ",token: " + token);

		//在头里返回给前端
		response.setHeader(TOKEN_KEY, token);

		//cookie默认浏览器进程就算了
		Cookie cookie = new Cookie(TOKEN_KEY, token);
		response.addCookie(cookie);

		Map<String, Object> vo = new HashMap<>();
		vo.put("status", 1);
		vo.put("massage", null);
		vo.put("data", token);
		response.setContentType("application/json");
		response.setStatus(HttpServletResponse.SC_OK);
		response.getWriter().write(objectMapper.writeValueAsString(vo));
	}

	//而账号密码错误则会调用这个方法
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
		System.out.println("账号或密码错误");
		Map<String, Object> vo = new HashMap<>();
		vo.put("status", 0);
		vo.put("massage", "账号或密码错误");
		vo.put("data", null);
		response.setContentType("application/json");
		response.setStatus(HttpServletResponse.SC_OK);
		response.getWriter().write(objectMapper.writeValueAsString(vo));
	}
}
