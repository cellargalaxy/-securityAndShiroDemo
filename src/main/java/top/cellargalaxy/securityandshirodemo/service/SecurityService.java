package top.cellargalaxy.securityandshirodemo.service;

import top.cellargalaxy.securityandshirodemo.model.SecurityUser;

/**
 * @author cellargalaxy
 * @time 2018/7/31
 */
public interface SecurityService {
	/**
	 * 查询账号
	 *
	 * @param username 账号
	 * @return 有则返之，无则返null
	 */
	SecurityUser getSecurityUser(String username);

	/**
	 * 制作该账号的token
	 *
	 * @param username 账号
	 * @return 账号的token
	 */
	String login(String username);

	/**
	 * 检查token是否合法
	 *
	 * @param token
	 * @return 合法则返回该token的SecurityUser对象
	 */
	SecurityUser checkToken(String token);
}
