import asyncio
import httpx
import re
from typing import Dict, Any, List

async def scan_webapp(target: str) -> Dict[str, Any]:
    if not target.startswith("http://") and not target.startswith("https://"):
        base_url = f"https://{target}"
    else:
        base_url = target
        
    result = {
        "cms_detected": None,
        "csrf_issues": [],
        "error_disclosure": False,
        "dangerous_js_patterns": [],
        "mixed_content_found": False,
        "findings": []
    }
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True) as client:
            try:
                resp = await client.get(base_url)
                html = resp.text
                headers = resp.headers
                
                # 1. FORMS WITHOUT CSRF TOKENS
                forms = re.findall(r'<form.*?</form>', html, re.IGNORECASE | re.DOTALL)
                for form in forms:
                    inputs = re.findall(r'<input[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*>', form, re.IGNORECASE)
                    has_csrf = False
                    for inp in inputs:
                        name_lower = inp.lower()
                        if any(k in name_lower for k in ['csrf', 'token', '_token', 'nonce']):
                            has_csrf = True
                            break
                    if not has_csrf:
                        result["csrf_issues"].append("Form missing CSRF token")
                        result["findings"].append({
                            "title": "Missing CSRF Token in Form",
                            "severity": "Medium",
                            "description": "A form was found without an obvious anti-CSRF token, which could allow Cross-Site Request Forgery.",
                            "evidence": form[:200] + "..." if len(form) > 200 else form
                        })

                # 2. PASSWORD FIELDS ON HTTP
                if base_url.startswith("http://"):
                    if re.search(r'<input[^>]*type=["\']?password["\']?', html, re.IGNORECASE):
                        result["findings"].append({
                            "title": "Password Field over Insecure HTTP",
                            "severity": "Critical",
                            "description": "A password input field is served over unencrypted HTTP, exposing credentials to interception.",
                            "evidence": "Found <input type='password'> on HTTP connection."
                        })

                # 4. SESSION COOKIE FLAGS
                for name, value in headers.multi_items():
                    if name.lower() == "set-cookie":
                        c_val = value.lower()
                        c_name = value.split("=")[0] if "=" in value else value
                        if "secure" not in c_val:
                            result["findings"].append({
                                "title": "Insecure Cookie (Missing Secure)",
                                "severity": "High",
                                "description": f"Cookie {c_name} is missing the Secure flag.",
                                "evidence": value
                            })
                        if "httponly" not in c_val:
                            result["findings"].append({
                                "title": "Insecure Cookie (Missing HttpOnly)",
                                "severity": "Medium",
                                "description": f"Cookie {c_name} is missing the HttpOnly flag.",
                                "evidence": value
                            })
                        if "samesite" not in c_val:
                            result["findings"].append({
                                "title": "Insecure Cookie (Missing SameSite)",
                                "severity": "Low",
                                "description": f"Cookie {c_name} is missing the SameSite attribute.",
                                "evidence": value
                            })

                # 5. MIXED CONTENT
                if base_url.startswith("https://"):
                    mixed = re.search(r'(src|href)=["\']http://', html, re.IGNORECASE)
                    if mixed:
                        result["mixed_content_found"] = True
                        result["findings"].append({
                            "title": "Mixed Content",
                            "severity": "Medium",
                            "description": "Page loaded over HTTPS contains resources loaded over HTTP.",
                            "evidence": "Found src='http://' or href='http://'"
                        })

                # 6. DANGEROUS JAVASCRIPT SINKS
                sinks = [
                    "document.write(", "innerHTML =", "eval(", 
                    "setTimeout('", 'setTimeout("', 
                    "setInterval('", 'setInterval("'
                ]
                for sink in sinks:
                    if sink in html:
                        result["dangerous_js_patterns"].append(sink)
                        result["findings"].append({
                            "title": f"Dangerous JavaScript Sink: {sink.strip()}",
                            "severity": "Medium",
                            "description": f"Potential XSS sink detected in page source: {sink}",
                            "evidence": sink
                        })

                # 9. SENSITIVE COMMENTS
                comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
                for comment in comments:
                    clower = comment.lower()
                    for sensitive in ["todo:", "fixme:", "password", "secret", "api_key", "token"]:
                        if sensitive in clower:
                            result["findings"].append({
                                "title": "Sensitive Information in HTML Comment",
                                "severity": "Medium",
                                "description": f"Found potentially sensitive keyword '{sensitive}' in HTML comments.",
                                "evidence": f"<!-- {comment[:100].strip()}... -->"
                            })
                            break

                # 7. CMS DETECTION
                cms = None
                if "/wp-content/" in html or re.search(r'<meta name="generator" content="WordPress', html, re.IGNORECASE):
                    cms = "WordPress"
                elif "/sites/default/" in html or "Drupal" in headers.get("X-Generator", ""):
                    cms = "Drupal"
                elif "/components/" in html:
                    cms = "Joomla"

                if not cms:
                    try:
                        wp_resp = await client.get(f"{base_url.rstrip('/')}/wp-login.php")
                        if wp_resp.status_code == 200 and "wp-submit" in wp_resp.text:
                            cms = "WordPress"
                    except Exception:
                        pass
                
                if not cms:
                    try:
                        jm_resp = await client.get(f"{base_url.rstrip('/')}/administrator/")
                        if jm_resp.status_code == 200 and "Joomla" in jm_resp.text:
                            cms = "Joomla"
                    except Exception:
                        pass

                if cms:
                    result["cms_detected"] = cms
                    result["findings"].append({
                        "title": f"CMS Detected: {cms}",
                        "severity": "Info",
                        "description": f"Identified {cms} as the content management system.",
                        "evidence": ""
                    })

                # Credential guessing is intentionally not performed. This
                # scanner remains non-invasive and only reports observable
                # fingerprinting evidence.

            except Exception as e:
                result["findings"].append({"title": "Main Page Request Error", "severity": "Info", "description": str(e), "evidence": ""})

            # 3. ERROR PAGE INFORMATION DISCLOSURE
            error_keywords = ["stack trace", "exception", "sql syntax", "mysql_fetch", "ora-", "syntax error"]
            test_urls = [
                f"{base_url.rstrip('/')}/nonexistent-page-xyz123",
                f"{base_url.rstrip('/')}/?id='"
            ]
            
            for t_url in test_urls:
                try:
                    err_resp = await client.get(t_url)
                    text_lower = err_resp.text.lower()
                    for kw in error_keywords:
                        if kw in text_lower:
                            result["error_disclosure"] = True
                            result["findings"].append({
                                "title": "Information Disclosure via Error Messages",
                                "severity": "High",
                                "description": f"Server exposed sensitive internal error information ('{kw}') when accessing {t_url}.",
                                "evidence": f"Found keyword '{kw}' in response."
                            })
                            break
                except Exception:
                    pass

    except Exception as e:
        result["findings"].append({
            "title": "Scanner Error",
            "severity": "Info",
            "description": f"Failed to complete web app scan: {str(e)}",
            "evidence": ""
        })

    return result
