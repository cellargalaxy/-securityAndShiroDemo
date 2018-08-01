package top.cellargalaxy.securityandshirodemo.controller;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authz.AuthorizationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;

/**
 * @author cellargalaxy
 * @time 2018/8/1
 */
@RestControllerAdvice
public class ExceptionController {

//	@ExceptionHandler(IncorrectCredentialsException.class)
//	public String handleIncorrectCredentialsException(Exception ex) {
//		return "Exception: 账号密码错误";
//	}
//
//	@ExceptionHandler(AuthorizationException.class)
//	public String handleAuthorizationException(Exception ex) {
//		return "Exception: 没有权限";
//	}
//
//	@ExceptionHandler(AccountException.class)
//	public String handleShiroException(Exception ex) {
//		return "Exception: " + ex.getMessage();
//	}
//	@ExceptionHandler(Exception.class)
//	public String handleException(Exception ex) {
//		return "Exception: " + ex.getMessage();
//	}
// 捕捉shiro的异常
@ResponseStatus(HttpStatus.UNAUTHORIZED)
@ExceptionHandler(ShiroException.class)
public String handle401(ShiroException e) {
	return "Exception: 401," + e;
}

	// 捕捉其他所有异常
	@ExceptionHandler(Exception.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String globalException(HttpServletRequest request, Throwable ex) {
	ex.printStackTrace();
		return "Exception: 未知异常";
	}
}
