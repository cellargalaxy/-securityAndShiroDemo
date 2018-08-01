package top.cellargalaxy.securityandshirodemo.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import top.cellargalaxy.securityandshirodemo.model.SecurityUser;
import top.cellargalaxy.securityandshirodemo.service.SecurityService;


/**
 * @author cellargalaxy
 * @time 2018/8/1
 */
@RestController
public class WebController {
	@Autowired
	private SecurityService securityService;

	@PostMapping("/login")
	public String login(@RequestParam("username") String username,
						@RequestParam("password") String password) {
		SecurityUser securityUser = securityService.getSecurityUser(username);
		if (securityUser != null && securityUser.getPassword().equals(password)) {
			return securityService.login(username);
		} else {
			return "账号或密码错误";
		}
	}

	@GetMapping("/article")
	public String article() {
		Subject subject = SecurityUtils.getSubject();
		if (subject.isAuthenticated()) {
			return "你已经登录";
		} else {
			return "你还没登录";
		}
	}

	@GetMapping("/require_auth")
	@RequiresAuthentication
	public String requireAuth() {
		return "你已经登录";
	}

	@GetMapping("/require_role")
	@RequiresRoles("admin")
	public String requireRole() {
		return "你有require_role角色";
	}

	@GetMapping("/require_permission")
	@RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
	public String requirePermission() {
		return "你有edit,view权限";
	}

	@RequestMapping(path = "/401")
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public String unauthorized() {
		return "未授权";
	}
}