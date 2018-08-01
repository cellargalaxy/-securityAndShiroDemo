package top.cellargalaxy.securityandshirodemo.shiro;

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 在BasicHttpAuthenticationFilter的方法应该有一定的调用顺序与逻辑
 * 虽然还没搞清楚他们之间的调用关系和执行顺序
 * 但是看网上的例子，有些是直接应有调用而没有使用父类的调用关系（例如isAccessAllowed方法）
 * preHandle:执行过滤前
 * onPreHandle:开始执行过滤
 * isLoginAttempt:是否要登录
 * isAccessAllowed:是否允许通过
 * onAccessDenied:拒绝通过
 * executeLogin:执行登录
 *
 * @author cellargalaxy
 * @time 2018/8/1
 */
public class JWTFilter extends BasicHttpAuthenticationFilter {
	public static final String TOKEN_KEY = "Authorization";

	//判断是否带有token，没有token跳去要登录
	@Override
	protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		String token = getToken(httpServletRequest);

		System.out.println("是否要登录token: " + token);

		return token != null;
	}

	//登录成功返回true，否则false
	@Override
	protected boolean executeLogin(ServletRequest request, ServletResponse response) {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		//从头，cookie，和参数里获取token
		String token = getToken(httpServletRequest);

		System.out.println("执行登录; token: " + token);

		//如果有token，把token设置在账号名登录一下
		//这里会调用Realm的doGetAuthenticationInfo方法来验证账号密码是否正确
		//如果错误会报异常，交到ExceptionController来处理，如果没报异常就是登录成功了
		if (token != null) {
			UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(token, token);
			getSubject(request, response).login(usernamePasswordToken);
			return true;
		}
		return false;
	}

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		if (isLoginAttempt(request, response)) {
			try {
				executeLogin(request, response);
			} catch (Exception e) {
			}
		}
		//这里都是返回true
		//如果executeLogin没有报异常，即登录成功，理应返回true
		//但是如果登录失败，返回false，不知为何他会报IncorrectCredentialsException异常，且无法被ExceptionController捕抓到
		//但是如果仍然返回true，他就会报UnauthenticatedException异常，且能被xceptionController捕抓到
		return true;
	}

	//对跨域提供支持
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
		httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
		httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
		httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
		//跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			httpServletResponse.setStatus(HttpStatus.OK.value());
			return false;
		}
		return super.preHandle(request, response);
	}

	private String getToken(HttpServletRequest httpServletRequest) {
		String token = httpServletRequest.getHeader(TOKEN_KEY);
		if (token != null) {
			return token;
		}
		Cookie[] cookies = httpServletRequest.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (TOKEN_KEY.equals(cookie.getName())) {
					return cookie.getValue();
				}
			}
		}
		return httpServletRequest.getParameter(TOKEN_KEY);
	}
}
