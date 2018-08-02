package piyo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import piyo.data.PiyoResponse;

import javax.servlet.http.HttpServletRequest;

@Controller
public class PiyoController {
	private static final Logger LOG = LoggerFactory.getLogger(PiyoController.class);

	/**
	 * index
	 */
	@RequestMapping(value = "/", method = RequestMethod.GET)
	private String index() {

		return "index";
	}

	/**
	 * userID入力画面
	 */
	@RequestMapping(value = "/userid", method = RequestMethod.GET)
	PiyoResponse user() {
		PiyoResponse response = new PiyoResponse();
		response.setTitle("userId入力成功");
		response.setDetail("本当ならここでそのユーザはパスワード認証なのかsaml認証なのか判定されます");
		response.setNextUrl("/login または /saml/login");

		return response;
	}

	/**
	 * success
	 */
	@RequestMapping(value = "/landing", method = RequestMethod.GET)
	private String landing(Model model, Authentication auth) {
		LOG.info("in landing:{}", auth.getName());
		return "landing";
		// PiyoResponse response = new PiyoResponse();
		// response.setTitle("SAML認証成功時にリダイレクトされるURL");
		// response.setNextUrl("認証OK: /success 認証NG:/userid");
		//
		// return response;
	}

	/**
	 * success
	 */
	@RequestMapping(value = "/success", method = RequestMethod.GET)
	PiyoResponse success() {
		PiyoResponse response = new PiyoResponse();
		response.setTitle("Successページ(認証成功)");
		response.setDetail("このページは認証済みユーザでないとみることができません。");

		return response;
	}

	// /login (POST) でログイン設定できます。
	// content-type : application/x-www-form-urlencoded
	// post body: username={username} password={password} (_csrf={CSRF-TOKEN})

	// /logout のURLをたたくとログイン情報を抹消します

	 /**
	 * 最初にcsrfを取得するためのAPI
	 *
	 * @param request
	 * @return
	 */
	 @RequestMapping(value = "/token", method = RequestMethod.GET)
	 String createToken(HttpServletRequest request) {
	 System.out.println(request.toString());
	 DefaultCsrfToken token = (DefaultCsrfToken) request.getAttribute("_csrf");
	 if (token == null) {
	 throw new RuntimeException("couldn't get a token. please check logs.");
	 }
	 return token.getToken();
	 }

}
