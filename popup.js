var Hasher=function(salt,passwd,loc,passlength) {
	function SHA256(s){
	 
		var chrsz   = 8;
		var hexcase = 0;
	 
		function safe_add (x, y) {
			var lsw = (x & 0xFFFF) + (y & 0xFFFF);
			var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
			return (msw << 16) | (lsw & 0xFFFF);
		}
	 
		function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
		function R (X, n) { return ( X >>> n ); }
		function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
		function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
		function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
		function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
		function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
		function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
	 
		function core_sha256 (m, l) {
			var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
			var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
			var W = new Array(64);
			var a, b, c, d, e, f, g, h, i, j;
			var T1, T2;
	 
			m[l >> 5] |= 0x80 << (24 - l % 32);
			m[((l + 64 >> 9) << 4) + 15] = l;
	 
			for ( var i = 0; i<m.length; i+=16 ) {
				a = HASH[0];
				b = HASH[1];
				c = HASH[2];
				d = HASH[3];
				e = HASH[4];
				f = HASH[5];
				g = HASH[6];
				h = HASH[7];
	 
				for ( var j = 0; j<64; j++) {
					if (j < 16) W[j] = m[j + i];
					else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
	 
					T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
					T2 = safe_add(Sigma0256(a), Maj(a, b, c));
	 
					h = g;
					g = f;
					f = e;
					e = safe_add(d, T1);
					d = c;
					c = b;
					b = a;
					a = safe_add(T1, T2);
				}
	 
				HASH[0] = safe_add(a, HASH[0]);
				HASH[1] = safe_add(b, HASH[1]);
				HASH[2] = safe_add(c, HASH[2]);
				HASH[3] = safe_add(d, HASH[3]);
				HASH[4] = safe_add(e, HASH[4]);
				HASH[5] = safe_add(f, HASH[5]);
				HASH[6] = safe_add(g, HASH[6]);
				HASH[7] = safe_add(h, HASH[7]);
			}
			return HASH;
		}
	 
		function str2binb (str) {
			var bin = Array();
			var mask = (1 << chrsz) - 1;
			for(var i = 0; i < str.length * chrsz; i += chrsz) {
				bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
			}
			return bin;
		}
	 
		function Utf8Encode(string) {
			string = string.replace(/\r\n/g,"\n");
			var utftext = "";
	 
			for (var n = 0; n < string.length; n++) {
	 
				var c = string.charCodeAt(n);
	 
				if (c < 128) {
					utftext += String.fromCharCode(c);
				}
				else if((c > 127) && (c < 2048)) {
					utftext += String.fromCharCode((c >> 6) | 192);
					utftext += String.fromCharCode((c & 63) | 128);
				}
				else {
					utftext += String.fromCharCode((c >> 12) | 224);
					utftext += String.fromCharCode(((c >> 6) & 63) | 128);
					utftext += String.fromCharCode((c & 63) | 128);
				}
	 
			}
	 
			return utftext;
		}
	 
		function binb2hex (binarray) {
			var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
			var str = "";
			for(var i = 0; i < binarray.length * 4; i++) {
				str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
				hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
			}
			return str;
		}
	 
		s = Utf8Encode(s);
		return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
	 
	}

	function InfiniteHash(code) {
		var pool='';
		var current=0;
		var index=0;
		// returns 0 to 255
		this.getNext=function() {
			if (pool.length<2) pool=SHA256(code+'|'+(index++).toString());
			var result=parseInt(pool.substr(0,2),16);
			pool=pool.substr(2);
			return result;
		};
		// returns 0 to limit-1, ignoring all that are higher than limit
		this.getNextLimited=function(limit) {
			var k;
			while(true) {
				k=this.getNext();
				if (k<Math.floor(256/limit)*limit) return k % limit;
			}
		};
	}

	function newpass(pass) {
		// charSets 0,1,2,3 are Symbols,Smallhand,Caps,Numbers
		var charSet=['!@#$%^&*()?/-+=~<>_','','',''];
			for (var i='a'.charCodeAt(0); i<='z'.charCodeAt('z'); ++i) charSet[1]+=String.fromCharCode(i);
			for (var i='A'.charCodeAt(0); i<='Z'.charCodeAt('z'); ++i) charSet[2]+=String.fromCharCode(i);
			for (var i=0; i<=9; ++i) charSet[3]+=i.toString();
		if (dontConfuse) {
			for (var i in charSet)
				charSet[i] = charSet[i].replace(/[0O1lI!i]/g,'')
		}
		var characters='';
		var mask=1;
		for (var i=0; i<4; ++i) {
			if ((maskAllow & mask) > 0) characters+=charSet[i];
			mask=mask*2;
		}
		var hash = new InfiniteHash(pass);
		var result='';
		for (var i=0; i<passlength; ++i)
			result+=characters[hash.getNextLimited(characters.length)];
		function ensureCharSet(index) {
			// get positions to enable forcing a char set without nullifying others
			var positions=[[],[],[],[]];
			for (var i=0; i<passlength; ++i) {
				var c = result[i];
				for (var ci=0; ci<4; ++ci)
					if (charSet[ci].indexOf(result[i])>=0) positions[ci].push(i);
			}
			if (positions[index].length>0) return;
			var replacable=[];
			for (var i=0; i<4; ++i)
				if (i!=index && positions[i].length>=2) replacable=replacable.concat(positions[i]);
			if (replacable.length==0) return; // all character sets are either absent or used only once length must be 4
			var posi = hash.getNextLimited(replacable.length);
			var pos = replacable[posi];
			var c=charSet[index][hash.getNextLimited(charSet[index].length)];
			result=result.substr(0,pos)+c+result.substr(pos+1);
		}
		var mask=1;
		for (var i=0; i<4; ++i) {
			if ((maskForce & mask) > 0) ensureCharSet(i);
			mask=mask*2;
		}
		return result;
	}

	var dontConfuse=true;	// omits O0l1I from the password characters
	// 1 - Symbols, 2-Smallhand, 4-Caps, 8-Numbers
	var maskAllow=15;
	var maskForce=maskAllow;

	return newpass(salt+'|'+passwd+'|'+loc);
}



/**
 * Get the current URL.
 *
 * @param {function(string)} callback - called when the URL of the current tab
 *   is found.
 */
function getCurrentTabUrl(callback) {
  // Query filter to be passed to chrome.tabs.query - see
  // https://developer.chrome.com/extensions/tabs#method-query
  var queryInfo = {
    active: true,
    currentWindow: true
  };

  chrome.tabs.query(queryInfo, function(tabs) {
    // chrome.tabs.query invokes the callback with a list of tabs that match the
    // query. When the popup is opened, there is certainly a window and at least
    // one tab, so we can safely assume that |tabs| is a non-empty array.
    // A window can only have one active tab at a time, so the array consists of
    // exactly one tab.
    var tab = tabs[0];

    // A tab is a plain object that provides information about the tab.
    // See https://developer.chrome.com/extensions/tabs#type-Tab
    var url = tab.url;

    // tab.url is only available if the "activeTab" permission is declared.
    // If you want to see the URL of other tabs (e.g. after removing active:true
    // from |queryInfo|), then the "tabs" permission is required to see their
    // "url" properties.
    console.assert(typeof url == 'string', 'tab.url should be a string');

    callback(url);
  });

  // Most methods of the Chrome extension APIs are asynchronous. This means that
  // you CANNOT do something like this:
  //
  // var url;
  // chrome.tabs.query(queryInfo, function(tabs) {
  //   url = tabs[0].url;
  // });
  // alert(url); // Shows "undefined", because chrome.tabs.query is async.
}

function extractDomain(url) {
    var domain;
    //find & remove protocol (http, ftp, etc.) and get domain
    if (url.indexOf("://") > -1) {
        domain = url.split('/')[2];
    }
    else {
        domain = url.split('/')[0];
    }

    //find & remove port number
    domain = domain.split(':')[0];
	
	//return only google.com for www.google.com, for example
	splitup = domain.split('.')
	if (splitup.length>2)
		domain=splitup[splitup.length-2]+'.'+splitup[splitup.length-1];

    return domain;
}

document.addEventListener('DOMContentLoaded', function() {
  chrome.storage.sync.get({
    masterPass: 'replace_this',
	lastWeak: '',
	passLength: '12'
  }, function(items) {
	  getCurrentTabUrl(function(url) {
			var loc = url;
			//if (loc.length>4 && loc.substr(0,4).toLowerCase()=='www.') loc=loc.substr(4);
			locSplit=loc.split('.');
			if (locSplit.length<=2) loc=locSplit[0];
			else loc=locSplit[1]+'.'+locSplit[2];
			var el_domain=document.getElementById('domain');
			el_domain.innerHTML=extractDomain(url);
			var el_weakpass=document.getElementById('weak_pass');
			var el_newp=document.getElementById('strong_pass');
			var textchange=function() {
				var passwd=el_weakpass.value;
				el_newp.value = Hasher(items.masterPass,passwd,loc,parseInt(items.passLength));
				chrome.storage.sync.set({
					lastWeak: el_weakpass.value
				});
			};
			el_weakpass.value=items.lastWeak;
			el_weakpass.onkeyup=textchange;
			el_newp.onfocus=function() {el_newp.select();}
			el_newp.onclick=function() {el_newp.select();}
			textchange();
			if (el_weakpass.value.length==0) el_weakpass.focus();
			else {el_newp.select(); el_newp.focus();}
	  });
  });
});