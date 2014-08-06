include "devicedetect.vcl";
import std;

# set default backend if no server cluster specified
backend default {
    .host = "";
    .port = "80";
	.first_byte_timeout = 120s;

}
 
# access control list for "purge": open to only localhost and other local nodes
acl purge {
	"localhost";
    "";
}

acl fuckingspam {
	"123.125.125.0"/24;
}
 
# vcl_recv is called whenever a request is received 
sub vcl_recv {

	if (client.ip ~ fuckingspam) {
        error 403;
    }
	
	if (
		req.http.user-agent ~ "^$"
		|| req.http.user-agent == "Mozilla/4.0"
		|| req.http.user-agent == "contype"
		|| req.http.user-agent == "YisouSpider"
		|| req.http.user-agent == "EasouSpider"

		)	{
				error 403 "You are banned from this site. lalalalalala";
			}
	
	
        # Serve objects up to 5 minutes past their expiry if the backend
        # is slow to respond.
        set req.grace = 300s;
        set req.http.X-Forwarded-For = client.ip;
        set req.backend = default;
		
	#手机跳转判断，先判定再重新bits.moegirl.org，顺序不能反
	if (req.http.host == "zh.moegirl.org"){
		if(req.http.Cookie !~ "direct_mobile") {
			call devicedetect;
			if (req.http.X-UA-Device ~ "^mobile" || req.http.X-UA-device ~ "^tablet") {
				error 750 "Moved Temporarily";
			}	
		}else if(req.http.Cookie ~ "direct_mobile=1" && req.url !~ "no_direct$") {
			error 751 "Moved Temporarily";
		}
	}
	
	#把bits.moegirl.org/XX/load.php 重定向到 XX.moegirl.org/load.php
	if (req.http.host ~ "bits\.moegirl\.org" && req.url~ "^/\w+/load\.php") {
		set req.http.host = regsub(req.url, "^/(\w+)/.*", "\1") + ".moegirl.org";
		set req.url = regsub(req.url, "^/(\w+)/", "/");
		}
 
        # This uses the ACL action called "purge". Basically if a request to
        # PURGE the cache comes from anywhere other than localhost, ignore it.
        if (req.request == "PURGE") {
			if (!client.ip ~ purge) {
				error 405 "Not allowed.";
			}
            return(lookup);
		}
 
        # Pass any requests that Varnish does not understand straight to the backend.
        if (req.request != "GET" && req.request != "HEAD" &&
            req.request != "PUT" && req.request != "POST" &&
            req.request != "TRACE" && req.request != "OPTIONS" &&
            req.request != "DELETE") 
            {return(pipe);}     /* Non-RFC2616 or CONNECT which is weird. */
 
        # Pass anything other than GET and HEAD directly.
        if (req.request != "GET" && req.request != "HEAD")
           {return(pass);}      /* We only deal with GET and HEAD by default */
		   
		#强制缓存/skins目录下内容
		if (req.url ~ "^/skins/") {
			return (lookup);
		}
		
		#pass any request with "special:"
		if (req.url ~ "Special:") {
			return(pass);
		}
		
		
		if (req.http.Cookie ~ "UserID") {
			if (!req.url ~ "^/load\.php") {
				return (pass);
			}
		} else {
			unset req.http.Cookie;
		}


        # Pass any requests with the "If-None-Match" header directly.
        if (req.http.If-None-Match)
           {return(pass);}
		 
 
        # Force lookup if the request is a no-cache request from the client.
        if (req.http.Cache-Control ~ "no-cache")
           {ban_url(req.url);}
 
        # normalize Accept-Encoding to reduce vary
	if (req.http.Accept-Encoding) {
		if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
			# No point in compressing these
			remove req.http.Accept-Encoding;
			#too large for our poor RAM
			return(pass);
		} elsif (req.http.Accept-Encoding ~ "gzip") {
			set req.http.Accept-Encoding = "gzip";
		} elsif (req.http.Accept-Encoding ~ "deflate" && req.http.user-agent !~ "MSIE") {
			set req.http.Accept-Encoding = "deflate";
		} else {
			# unkown algorithm
			remove req.http.Accept-Encoding;
		}
	}
 
        return(lookup);
}
 
sub vcl_pipe {
    # Note that only the first request to the backend will have
    # X-Forwarded-For set.  If you use X-Forwarded-For and want to
    # have it set for all requests, make sure to have:
    # set req.http.connection = "close";
 
	# This is otherwise not necessary if you do not do any request rewriting.
    set req.http.connection = "close";
}


sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }
    return (hash);
}
 
# Called if the cache has a copy of the page.
sub vcl_hit {
        if (req.request == "PURGE") 
            {ban_url(req.url);
            error 200 "Purged";}
 
        if (!obj.ttl > 0s)
           {return(pass);}
}
 
# Called if the cache does not have a copy of the page.
sub vcl_miss {
        if (req.request == "PURGE") 
           {error 200 "Not in cache";}
}
 
# Called after a document has been successfully retrieved from the backend.
sub vcl_fetch {
# 		如果后端服务器返回错误，则进入 saintmode
#		if (beresp.status == 500 || beresp.status == 501 || beresp.status == 502 || beresp.status == 503 || beresp.status == 504) {
#			set req.http.host = "status";
#			set beresp.saintmode = 5s;
#			return (restart);
#		}

#   让Vary 只包含 Accept-Encoding 和 Cookie, 防止产生过多的cache object
    if (beresp.http.Vary) {
      if (beresp.http.Vary ~ "Accept-Encoding") {
        set beresp.http.tempVary = "Accept-Encoding";
      }
      if (beresp.http.Vary ~ "Cookie") {
        if (beresp.http.tempVary) {
          set beresp.http.tempVary = beresp.http.tempVary + ",Cookie";
        } else {
          set beresp.http.tempVary = "Cookie";
        }
      }

      if (beresp.http.tempVary) {
        set beresp.http.Vary = beresp.http.tempVary;
        remove beresp.http.tempVary;
      } else {
        remove beresp.http.Vary;
      }
    }

		
        # set minimum timeouts to auto-discard stored objects
#       set beresp.prefetch = -30s;
        set beresp.grace = 30m;
 
        if (beresp.ttl < 48h) {
          set beresp.ttl = 48h;}
 
        if (!beresp.ttl > 0s) 
            {return(hit_for_pass);}
 
         if ( ! beresp.http.Set-Cookie ) {
             set beresp.ttl = 1h;
             return (deliver);}

#       if (beresp.http.Cache-Control ~ "(private|no-cache|no-store)") 
#           {return(hit_for_pass);}
 
        if (req.http.Authorization && !beresp.http.Cache-Control ~ "public") 
            {return(hit_for_pass);}

 }
 
sub vcl_deliver {
    if (obj.hits > 0) {
            set resp.http.X-Cache = "HIT";
    } else {
            set resp.http.X-Cache = "MISS";
    }
}

sub vcl_error {
	if(obj.status == 750) {
		set obj.http.Content-Type = "text/html; charset=utf-8"; 
		synthetic {"
   <html>
    <head>
     <script language="javascript">
       <!--
         function confirmation() {
			var d = new Date();
			d.setTime(d.getTime()+(60*60*1000));
			var expires = "expires="+d.toGMTString();
			var msg_text = unescape("%u70B9%u51FB%22%u786E%u5B9A%22%u8DF3%u8F6C%u5230%u624B%u673A%u7248%u9875%u9762%uFF0C%u70B9%u51FB%22%u53D6%u6D88%22%u7EE7%u7EED%u8BBF%u95EE");
           //var answer = confirm("Press \"OK\" to be redirected to the mobile page or \"Cancel\" to continue.");
		   var answer = confirm(msg_text);
           if (answer) {
			document.cookie = "direct_mobile=1; " + expires;
             window.location = "http://m.moegirl.org"} + req.url + {"";
           }
           else { 
			 document.cookie = "direct_mobile=0; " + expires;
             window.location = "http://zh.moegirl.org"} + req.url + {"";
           }
         } //-->
      </script>
    </head>
    <body onload="confirmation();">
      <p></p>
    </body>
  </html>
    "};
		set obj.status = 200;
		return(deliver);
	} else if(obj.status == 751) {
		set obj.http.Location = "http://m.moegirl.org" + req.url;
		set obj.status = 302;
		return(deliver);
	}
	
	# For 500 error 500错误用设置
	if (obj.status >= 500 && obj.status <= 505) {
		synthetic(std.fileread("/etc/varnish/50X.html"));
		return(deliver);
	}
    return (deliver);
}
