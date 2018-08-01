package top.cellargalaxy.securityandshirodemo.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;
import top.cellargalaxy.securityandshirodemo.service.SecurityService;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 在BasicHttpAuthenticationFilter的方法有一定的调用顺序与逻辑
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

	/**
	 * 判断用户是否想要登入。
	 * 检测header里面是否包含Authorization字段即可
	 */
	@Override
	protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
		HttpServletRequest req = (HttpServletRequest) request;
		String authorization = req.getHeader("Authorization");
		return authorization != null;
	}

	/**
	 *
	 */
	@Override
	protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		String token = httpServletRequest.getHeader("Authorization");

		UsernamePasswordToken usernamePasswordToken=new UsernamePasswordToken(token,token);
		// 提交给realm进行登入，如果错误他会抛出异常并被捕获
		getSubject(request, response).login(usernamePasswordToken);
		// 如果没有抛出异常则代表登入成功，返回true
		return true;
	}

	/**
	 * 这里我们详细说明下为什么最终返回的都是true，即允许访问
	 * 例如我们提供一个地址 GET /article
	 * 登入用户和游客看到的内容是不同的
	 * 如果在这里返回了false，请求会被直接拦截，用户看不到任何东西
	 * 所以我们在这里返回true，Controller中可以通过 subject.isAuthenticated() 来判断用户是否登入
	 * 如果有些资源只有登入用户才能访问，我们只需要在方法上面加上 @RequiresAuthentication 注解即可
	 * 但是这样做有一个缺点，就是不能够对GET,POST等请求进行分别过滤鉴权(因为我们重写了官方的方法)，但实际上对应用影响不大
	 */
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		if (isLoginAttempt(request, response)) {
			try {
				executeLogin(request, response);
			} catch (Exception e) {
				try {
					HttpServletResponse httpServletResponse = (HttpServletResponse) response;
					httpServletResponse.sendRedirect("/401");
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		}
		return true;
	}

	/**
	 * 对跨域提供支持
	 */
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
		httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
		httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
		httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
		// 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			httpServletResponse.setStatus(HttpStatus.OK.value());
			return false;
		}
		return super.preHandle(request, response);
	}

//	//判断是否带有token，没有token跳去要登录
//	@Override
//	protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
//		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
//
//		String token = httpServletRequest.getParameter(TOKEN_KEY);
//
//		System.out.println("是否要登录token: " + token);
//
//		return false;//token != null;
//	}
//
//	//登录成功返回true，否则false
//	@Override
//	protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
//		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
//		//从头，cookie，和参数里获取token
//		String token = httpServletRequest.getHeader(TOKEN_KEY);
//		if (token == null) {
//			Cookie[] cookies = httpServletRequest.getCookies();
//			if (cookies != null) {
//				for (Cookie cookie : cookies) {
//					if (cookie.getName().equals(TOKEN_KEY)) {
//						token = cookie.getValue();
//						break;
//					}
//				}
//			}
//		}
//		if (token == null) {
//			token = httpServletRequest.getParameter(TOKEN_KEY);
//		}
//
//		System.out.println("执行登录; token: " + token);
//
//		//如果有token，把token设置在账号名登录一下
//		//这里会调用Realm的doGetAuthenticationInfo方法来验证账号密码是否正确
//		//如果错误会报异常，交到ExceptionController来处理，如果没报异常就是登录成功了
//		if (token != null) {
//			UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(token, token);
//			getSubject(request, response).login(usernamePasswordToken);
//			return true;
//		}
//		return false;
//	}
//
//	//对跨域提供支持
//	@Override
//	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
//		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
//		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
//		httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
//		httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
//		httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
//		//跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
//		if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
//			httpServletResponse.setStatus(HttpStatus.OK.value());
//			return false;
//		}
//		return super.preHandle(request, response);
//	}
}
