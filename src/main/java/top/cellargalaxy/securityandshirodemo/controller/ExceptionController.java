package top.cellargalaxy.securityandshirodemo.controller;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.http.HttpStatus;
//import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * @author cellargalaxy
 * @time 2018/8/1
 */
@RestControllerAdvice
public class ExceptionController {
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	@ExceptionHandler(UnauthenticatedException.class)
	public String handle401(UnauthenticatedException e) {
		return "Exception: 未登录";
	}

	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	@ExceptionHandler(UnauthorizedException.class)
	public String handle401(UnauthorizedException e) {
		return "Exception: 无权限访问";
	}

//	@ResponseStatus(HttpStatus.UNAUTHORIZED)
//	@ExceptionHandler(AccessDeniedException.class)
//	public String handle401(AccessDeniedException e) {
//		return "Exception: 无权限访问";
//	}

	@ExceptionHandler(Exception.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String globalException(Throwable ex) {
		ex.printStackTrace();
		return "Exception: 未知异常";
	}
}
