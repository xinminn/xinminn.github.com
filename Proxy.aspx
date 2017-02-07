<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Page Language="C#" EnableViewStateMac="false" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<script runat="server">

	string returnUrl;
    protected void Page_Load(object sender, EventArgs e)
    {
		try
		{
			returnUrl = Request.QueryString.Get("ReturnUrl");
			if (Request.RequestType.ToUpper() == "GET")
			{
				string queryStringTemp = "";
				foreach (String key in Request.QueryString.AllKeys)
				{
					if (key != "ReturnUrl" && key != "Referer")
					{
						queryStringTemp += "&" + key + "=" + Request.QueryString[key];
					}
				}

				if (queryStringTemp != "") returnUrl = returnUrl + "?" + queryStringTemp;
			}

			if (string.IsNullOrEmpty(returnUrl)) returnUrl = Request.Form["ReturnUrl"];
			if (!string.IsNullOrEmpty(returnUrl))
			{
				//构造http请求 
				HttpWebRequest httpRequest = (HttpWebRequest)HttpWebRequest.Create(returnUrl);
				foreach (string key in Request.Headers.AllKeys)
				{
					try
					{
						if (key != "Cookie")
						{
							httpRequest.Headers.Add(key, Request.Headers[key]);
						}
					}
					catch { }
				}

				//设置Range,以支持断点续传
				string range = Request.Headers["Range"];
				string rangeFrom = "";
				string rangeTo = "";
				try
				{
					rangeFrom = range.Split(new char[] { '=', '-' })[1];
				}
				catch { }

				try
				{
					rangeTo = range.Split(new char[] { '=', '-' })[2];
				}
				catch { }

				if (rangeFrom.Length > 0 && rangeTo.Length > 0)
				{
					httpRequest.AddRange(int.Parse(rangeFrom), int.Parse(rangeTo));
				}

				if (rangeFrom.Length > 0)
				{
					httpRequest.AddRange(int.Parse(rangeFrom));
				}

				//设置Cookies
				foreach (string cookieItem in Request.Cookies.AllKeys)
				{
					try
					{
						string domain = cookieItem.Substring(2, cookieItem.IndexOf("]") - 2);
						string cookie = cookieItem.Substring(cookieItem.IndexOf("[/]") + 4).Replace("]", "");
						if (returnUrl.IndexOf(domain) > -1)
						{
							if (string.IsNullOrEmpty(httpRequest.Headers["Cookie"]))
							{
								httpRequest.Headers.Set("Cookie", httpRequest.Headers["Cookie"] + cookie + "=" + Request.Cookies[cookieItem].Value);
							}
							else
							{
								httpRequest.Headers.Set("Cookie", httpRequest.Headers["Cookie"] + ";" + cookie + "=" + Request.Cookies[cookieItem].Value);
							}
						}
					}
					catch { }
				}

				httpRequest.Accept = Request.Headers["Accept"];
				httpRequest.ContentLength = Request.ContentLength;
				httpRequest.ContentType = Request.ContentType;
				httpRequest.Method = Request.HttpMethod;

				//设置代理
				if (System.Configuration.ConfigurationManager.AppSettings["useProxy"] == "true")
				{
					WebProxy proxy = new WebProxy(
						System.Configuration.ConfigurationManager.AppSettings["proxyAddress"],
						int.Parse(System.Configuration.ConfigurationManager.AppSettings["proxyPort"])
						);
					
					proxy.Credentials = new NetworkCredential(
						System.Configuration.ConfigurationManager.AppSettings["proxyUsername"],
						System.Configuration.ConfigurationManager.AppSettings["proxyPassword"],
						System.Configuration.ConfigurationManager.AppSettings["proxyDomain"]
						);
					
					httpRequest.Proxy = proxy;
				}
				
				//设置Referer
				string referer = "";
				if (Request.RequestType.ToUpper() == "GET")
				{
					referer = Request.QueryString.Get("Referer");
				}
				else
				{
					referer = Request.Form["Referer"];
				}

				try
				{
					httpRequest.Referer = referer;
				}
				catch { }

				try
				{
					httpRequest.UserAgent = Request.UserAgent;
				}
				catch { }

				//设置Cookies
				CookieContainer serverCookieContainer = new CookieContainer();
				for (int i = 0; i < Request.Cookies.Count; i++)
				{
					CookieContainer tempContainer = LoadCookies(Request.Cookies[i].Value);
					CookieCollection tempCollection = tempContainer.GetCookies(httpRequest.Address);
					foreach (Cookie cookie in tempCollection)
					{
						serverCookieContainer.Add(cookie);
					}	
				}

				httpRequest.CookieContainer = serverCookieContainer;
				
				string method = Request.HttpMethod;
				if (method.ToUpper().Trim() != "GET")
				{
					//发送POST请求
					byte[] buffer = new byte[4096];
					int requestLen = Request.InputStream.Read(buffer, 0, buffer.Length);

					//首包数据剔除多余的ReturnUrl和Referer参数
					int firtReqPos = 0;
					string firstRequest = Encoding.ASCII.GetString(buffer, 0, requestLen);
					System.Text.RegularExpressions.Regex firtReqRegex = new Regex("^ReturnUrl=[\\S\\s]*?&Referer=[\\S\\s]*?&");
					if (firtReqRegex.IsMatch(firstRequest))
					{
						firtReqPos = firtReqRegex.Matches(firstRequest)[0].Length;
					}

					httpRequest.ContentLength = Request.ContentLength - firtReqPos;
					Stream reqStream = httpRequest.GetRequestStream();

					reqStream.Write(buffer, firtReqPos, requestLen - firtReqPos);
					reqStream.Flush();

					while (requestLen > 0)
					{
						requestLen = Request.InputStream.Read(buffer, 0, buffer.Length);
						if (requestLen == 0) break;
						reqStream.Write(buffer, 0, requestLen);
						reqStream.Flush();
					}
				}

				HttpWebResponse httpResponse = (HttpWebResponse)httpRequest.GetResponse();

				//转换Cookies
				try
				{
					string base64CookiesStr = SaveCookies(serverCookieContainer);
					HttpCookie responseCookie = new HttpCookie(httpRequest.Address.Host, base64CookiesStr);
					responseCookie.Expires = DateTime.Now.AddDays(7);
					Response.SetCookie(responseCookie);
				}
				catch { }
				
				//判断内容类型和字符集
				if (httpResponse.ContentType.Substring(0, 4).ToLower() == "text" || httpResponse.ContentType.ToLower() == "application/javascript")
				{
					//如果是文本

					//判断网页是否经过压缩
					Stream responseStream;
					switch (httpResponse.ContentEncoding.ToUpper())
					{
						case "GZIP": responseStream = new System.IO.Compression.GZipStream(httpResponse.GetResponseStream(), System.IO.Compression.CompressionMode.Decompress); break;
						case "DEFLATE": responseStream = new System.IO.Compression.DeflateStream(httpResponse.GetResponseStream(), System.IO.Compression.CompressionMode.Decompress); break;
						default: responseStream = httpResponse.GetResponseStream(); break;
					}

					//System.Text.Encoding responseEncoding;
					//switch (httpResponse.CharacterSet.ToUpper())
					//{
					//    case "GB2312": responseEncoding = System.Text.Encoding.GetEncoding("gb2312"); break;
					//    case "UTF-8": responseEncoding = System.Text.Encoding.UTF8; break;
					//    case "ISO-8859-1": responseEncoding = System.Text.Encoding.GetEncoding("gb2312"); break;
					//    case "GBK": responseEncoding = System.Text.Encoding.Unicode; break;
					//    default: responseEncoding = TryGetEncoding(httpResponse.CharacterSet); break;
					//}

					//System.IO.StreamReader responseReader = new System.IO.StreamReader(responseStream, responseEncoding);
					//Response.Write(ProcessHtml(responseReader.ReadToEnd()));
					
					Response.ContentType = httpResponse.ContentType;
					Response.StatusCode = httpResponse.StatusCode.GetHashCode();
					Response.StatusDescription = httpResponse.StatusDescription;

					Encoding responseEncoding;
					string responseString = GetString(responseStream, out responseEncoding);


					byte[] responseByte = responseEncoding.GetBytes(ProcessHtml(responseString));
					Response.OutputStream.Write(responseByte, 0, responseByte.Length);
					Response.Flush();
				}
				else
				{
					//直接二进制输出
					Stream responseStream = httpResponse.GetResponseStream();

					foreach (string key in httpResponse.Headers.AllKeys)
					{
						Response.AppendHeader(key, httpResponse.Headers[key]);
					}

					if (string.IsNullOrEmpty(httpResponse.Headers["Content-Disposition"]))
					{
						Response.AppendHeader("Content-Disposition", "inline;filename=" + HttpUtility.UrlEncode(GetFileName(returnUrl)));
					}

					Response.Charset = httpResponse.CharacterSet;
					Response.ContentType = httpResponse.ContentType;
					Response.StatusCode = httpResponse.StatusCode.GetHashCode();
					Response.StatusDescription = httpResponse.StatusDescription;

					byte[] buffer = new byte[4096];
					int responseLen = 0;
					do
					{
						Response.Flush();
						responseLen = responseStream.Read(buffer, 0, buffer.Length);
						if (responseLen == 0) break;
						Response.OutputStream.Write(buffer, 0, responseLen);
					}
					while (responseLen > 0);

				}
				
				Response.Flush();
			}
			else
			{
				Response.Write("<html><head><title>WEB在线代理</title></head><body style=\"font-size:14px\"><form id=\"ProxyForm\" method=\"get\" action=\"Proxy.aspx\"><div>输入完整URL:&nbsp;&nbsp;<input type=\"text\" id=\"ReturnUrl\" name=\"ReturnUrl\" value=\"http://\" style=\"width:400px\" /> <input type=\"submit\" value=\"GO!\" /> <input type=\"button\" value=\"ViewLink\" onclick=\"javascript:ViewLink.href='Proxy.aspx?ReturnUrl='+encodeURIComponent(document.all.ReturnUrl.value);\"/> <a id='ViewLink' href=\"#\">Link</a></div></form></body></html>");
			}

		}
		catch (Exception ex)
		{
			try
			{
				Response.Write(ex.Message);
			}
			catch { }
		}
		return;
	}

	private string GetString(Stream stream, out Encoding encoding)
	{
		byte[] buffer;
		using (MemoryStream tempStream = new MemoryStream())
		{
			buffer = new byte[4096];
			int responseLen = 0;
			do
			{
				responseLen = stream.Read(buffer, 0, buffer.Length);
				if (responseLen == 0) break;
				tempStream.Write(buffer, 0, responseLen);
			}
			while (responseLen > 0);

			buffer = tempStream.ToArray();
		}

		encoding = GetEncoding(buffer);
		return encoding.GetString(buffer);
	}

	public Encoding GetEncoding(byte[] data)
	{
		//byte[] unicode = new byte[] { 0xFF, 0xFE, 0x41 };
		//byte[] unicodeBig = new byte[] { 0xFE, 0xFF, 0x00 };
		//byte[] utf8 = new byte[] { 0xEF, 0xBB, 0xBF }; //带BOM
		
		Encoding reVal = Encoding.Default;
		if (IsNoBomUtf8(data) || (data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF))
		{
			reVal = Encoding.UTF8;
		}
		else if (data[0] == 0xFE && data[1] == 0xFF && data[2] == 0x00)
		{
			reVal = Encoding.BigEndianUnicode;
		}
		else if (data[0] == 0xFF && data[1] == 0xFE && data[2] == 0x41)
		{
			reVal = Encoding.Unicode;
		}
		return reVal;
	}
	
	///<summary>
	/// 判断是否是不带 BOM 的 UTF8 格式
	/// </summary>
	/// <param name="data"></param>
	/// <returns></returns>
	private bool IsNoBomUtf8(byte[] data)
	{
		int charByteCounter = 1;	//计算当前正分析的字符应还有的字节数 
		byte curByte;				//当前分析的字节.
		for (int i = 0; i < data.Length; i++)
		{
			curByte = data[i];
			if (charByteCounter == 1)
			{
				if (curByte >= 0x80)
				{
					//判断当前
					while (((curByte <<= 1) & 0x80) != 0)
					{
						charByteCounter++;
					}
					//标记位首位若为非0 则至少以2个1开始 如:110XXXXX...........1111110X
					if (charByteCounter == 1 || charByteCounter > 6)
					{
						return false;
					}
				}
			}
			else
			{
				//若是UTF-8 此时第一位必须为1
				if ((curByte & 0xC0) != 0x80)
				{
					return false;
				}
				charByteCounter--;
			}
		}
		if (charByteCounter > 1)
		{
			return false;
		}
		return true;
	}

	public List<Cookie> GetAllCookies(CookieContainer cc)
	{
		List<Cookie> lstCookies = new List<Cookie>();

		Hashtable table = (Hashtable)cc.GetType().InvokeMember("m_domainTable",
			System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.GetField |
			System.Reflection.BindingFlags.Instance, null, cc, new object[] { });

		foreach (object pathList in table.Values)
		{
			SortedList lstCookieCol = (SortedList)pathList.GetType().InvokeMember("m_list",
				System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.GetField
				| System.Reflection.BindingFlags.Instance, null, pathList, new object[] { });
			foreach (CookieCollection colCookies in lstCookieCol.Values)
				foreach (Cookie c in colCookies) lstCookies.Add(c);
		}

		return lstCookies;
	}

	private string SaveCookies(CookieContainer cc)
	{
		List<Cookie> lstCookies = new List<Cookie>();

		Hashtable table = (Hashtable)cc.GetType().InvokeMember("m_domainTable",
			System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.GetField |
			System.Reflection.BindingFlags.Instance, null, cc, new object[] { });

		foreach (object pathList in table.Values)
		{
			SortedList lstCookieCol = (SortedList)pathList.GetType().InvokeMember("m_list",
				System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.GetField
				| System.Reflection.BindingFlags.Instance, null, pathList, new object[] { });
			foreach (CookieCollection colCookies in lstCookieCol.Values)
				foreach (Cookie c in colCookies) lstCookies.Add(c);
		}
		
		StringBuilder cookiesStr = new StringBuilder();
		foreach (Cookie cookie in lstCookies)
		{
			cookiesStr.AppendFormat("{0};{1};{2};{3};{4};{5}\r\n",
				cookie.Domain, cookie.Name, cookie.Path, cookie.Port,
				cookie.Secure.ToString(), cookie.Value);
		}
		return Convert.ToBase64String(Encoding.UTF8.GetBytes(cookiesStr.ToString()));
	}

	private CookieContainer LoadCookies(string base64Str)
	{
		CookieContainer cookieContainer = new CookieContainer();
		try
		{
			string cookiesStr = Encoding.UTF8.GetString(Convert.FromBase64String(base64Str));
			string[] cookies = cookiesStr.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
			foreach (string c in cookies)
			{
				string[] cc = c.Split(";".ToCharArray());
				Cookie ck = new Cookie();
				ck.Discard = false;
				ck.Domain = cc[0];
				ck.Expired = true;
				ck.HttpOnly = true;
				ck.Name = cc[1];
				ck.Path = cc[2];
				ck.Port = cc[3];
				ck.Secure = bool.Parse(cc[4]);
				ck.Value = cc[5];
				cookieContainer.Add(ck);
			}
		}
		catch { }
		return cookieContainer;
	}
	
	private string GetFileName(string url)
	{
		Uri uri = new Uri(url);
		string[] split = uri.AbsolutePath.Split('/');
		string filename = split[split.Length - 1];
		return string.IsNullOrEmpty(filename) ? "Proxy.aspx" : filename;
	}

	private string ProcessHtml(string html)
	{
		//处理标记 A,LINK
		System.Text.RegularExpressions.Regex aRegex = new Regex("(?i)(?<=(<[\\s\\S]+?href[\\s]*?=[\\s]*?['\"]))([\\S]+?)(?=([\"']|>))");
		try
		{
			html = aRegex.Replace(html, new MatchEvaluator(CorrectString));
		}
		catch { }

		//处理标记 IMG 和 SCRIPT
		//System.Text.RegularExpressions.Regex IMGRegex = new Regex("(?i)(?<=(<[\\s\\S]+?src[\\s]*?=[\\s]*?['\"]))([\\S]+?)(?=([\"']|>))");
		System.Text.RegularExpressions.Regex imgRegex = new Regex("(?i)(?<=(<[\\s\\S]+?src[\\s]*?=[\\s]*?))([\\S]+?)(?=([\\s\"']|>))");
		try
		{
			html = imgRegex.Replace(html, new MatchEvaluator(CorrectString));
		}
		catch { }

		//处理url(***)
		System.Text.RegularExpressions.Regex urlRegex = new Regex("(?i)(?<=(url[\\s]*?[\\(][\\s]*?['\"]{0,1}))([\\S]+?)(?=([\"'\\)]))");
		try
		{
			html = urlRegex.Replace(html, new MatchEvaluator(CorrectString));
		}
		catch { }

		//处理form
		System.Text.RegularExpressions.Regex formRegex = new Regex("(?i)<form[\\s\\S]+?>");
		try
		{
			html = formRegex.Replace(html, new MatchEvaluator(FormCorrectString));
		}
		catch { }


		return html;
	}

	private string CorrectString(Match match)
	{
		try
		{
			if (match.Length == 0 || match.Value.StartsWith("#") || match.Value.ToLower().StartsWith("javascript:")) return match.Value;
			string returnString = match.Value;
			string starTag = "";
			string endTag = "";

			if (match.Value.StartsWith("'"))
			{
				starTag = "'";
				returnString = returnString.Substring(1);
			}

			if (match.Value.StartsWith("\""))
			{
				starTag = "\"";
				returnString = returnString.Substring(1);
			}

			if (match.Value.EndsWith("'"))
			{
				endTag = "'";
				returnString = returnString.Substring(0, returnString.Length - 1);
			}

			if (match.Value.EndsWith("\""))
			{
				endTag = "\"";
				returnString = returnString.Substring(0, returnString.Length - 1);
			}

			return starTag + "Proxy.aspx?" + "Referer=" + HttpUtility.UrlEncode(returnUrl) + "&ReturnUrl=" + HttpUtility.UrlEncode(GetAbsolutePath(returnUrl, HttpUtility.HtmlDecode(returnString))) + endTag;
		}
		catch
		{
			return match.Value;
		}
	}

	//处理form
	private string FormCorrectString(Match match)
	{
		try
		{
			string formString = match.Value;
			System.Text.RegularExpressions.Regex actionRegex = new Regex("(?i)(?<=(<form[\\s\\S]+?action[\\s]*?=[\\s]*?['\"]))([\\S]+?)(?=([\"']|>))");
			if (!actionRegex.IsMatch(formString)) return formString;
			string action = actionRegex.Match(formString).Value;
			formString = actionRegex.Replace(formString, "Proxy.aspx");
			formString = formString + "<input type='hidden' name='ReturnUrl' value='" + GetAbsolutePath(returnUrl, action) + "'/>" + "<input type='hidden' name='Referer' value='" + returnUrl + "'/>";

			return formString;
		}
		catch
		{
			return match.Value;
		}
	}

	//相对地址转换成绝对地址
	private static string GetAbsolutePath(string sourcepath, string relativepath)
	{
		try
		{
			Uri baseUri = new Uri(sourcepath);
			Uri absoluteUri = new Uri(baseUri, relativepath);
			return absoluteUri.ToString();
		}
		catch
		{
			return relativepath;
		}
	}
</script>
