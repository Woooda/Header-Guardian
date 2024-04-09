import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.exception

def analyze_headers(url):
    def check_dns_record(record_type, domain):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return True if answers else False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return False

    try:
        response = requests.get(url)
        headers = response.headers
        soup = BeautifulSoup(response.content, "html.parser")
        domain = url.split('/')[2]

        security_report = []

        if not soup.find("meta", {"name": "referrer", "content": "no-referrer"}):
            security_report.append(("Метатег Referrer", "Отсутствует", "Низкая", "Добавьте метатег 'referrer' с 'no-referrer' для предотвращения Same Site Scripting."))

        if not check_dns_record("TXT", domain):
            security_report.append(("SPF запись", "Отсутствует", "Низкая", "Добавьте SPF запись в настройки DNS вашего домена, чтобы помочь предотвратить подделку электронной почты."))

        if not check_dns_record("TXT", f"_dmarc.{domain}"):
            security_report.append(("DMARC запись", "Отсутствует", "Низкая", "Добавьте DMARC запись в настройки DNS вашего домена, чтобы помочь защититься от подделки электронной почты и фишинга."))

        if requests.get(f"{url}/admin", timeout=5).status_code == 200:
            security_report.append(("Публичная страница администратора", "Доступна", "Высокая", "Ограничьте доступ к вашей странице администратора для конкретных IP-адресов и/или включите аутентификацию."))
        if "Index of" in requests.get(f"{url}/test_non_existent_directory", timeout=5).text:
            security_report.append(("Отображение содержимого каталога", "Включено", "Средняя", "Отключите отображение содержимого каталога, чтобы предотвратить несанкционированный доступ к файлам и папкам вашего веб-сайта."))

        security_headers = [
            ("Content-Security-Policy", "Реализуйте политику безопасности контента (CSP) для предотвращения межсайтового скриптинга (XSS) и других атак внедрения кода."),
            ("X-Content-Type-Options", "Установите заголовок 'X-Content-Type-Options' в 'nosniff', чтобы предотвратить анализ типов MIME."),
            ("X-Frame-Options", "Установите заголовок 'X-Frame-Options' в 'DENY' или 'SAMEORIGIN', чтобы защититься от clickjacking."),
            ("X-XSS-Protection", "Установите заголовок 'X-XSS-Protection' в '1; mode=block', чтобы включить защиту от XSS в старых браузерах."),
            ("Strict-Transport-Security", "Реализуйте Strict Transport Security (HSTS), чтобы обеспечить безопасные соединения."),
        ]
        for header, fix in security_headers:
            if header not in headers:
                security_report.append((header, "Отсутствует", "Средняя", fix))

        set_cookie = headers.get("Set-Cookie", "")
        if "Secure" not in set_cookie or "HttpOnly" not in set_cookie:
            security_report.append(("Куки", "Небезопасные", "Высокая", "Установите флаги 'Secure' и 'HttpOnly' для куки, чтобы защитить их от перехвата и доступа через JavaScript."))

        info_disclosure_headers = [
            ("Server", "Удалите или обфусцируйте заголовок 'Server', чтобы избежать раскрытия информации о сервере."),
            ("X-Powered-By", "Удалите или обфусцируйте заголовок 'X-Powered-By', чтобы избежать раскрытия информации о технологическом стеке."),
            ("X-AspNet-Version", "Удалите или обфусцируйте заголовок 'X-AspNet-Version', чтобы избежать раскрытия информации о версии ASP.NET."),
        ]
        for header, fix in info_disclosure_headers:
            if header in headers:
                security_report.append((header, f"Значение: {headers[header]}", "Низкая", fix))

        access_control_allow_origin = headers.get("Access-Control-Allow-Origin", "")
        if access_control_allow_origin == "*":
            security_report.append(("Access-Control-Allow-Origin", "Некорректно настроено", "Высокая", "Ограничьте заголовок 'Access-Control-Allow-Origin' для конкретных доверенных доменов или избегайте использования символа '*' (звездочки)."))

        content_type = headers.get("Content-Type", "")
        x_content_type_options = headers.get("X-Content-Type-Options", "")
        if content_type.startswith("text/html") and x_content_type_options != "nosniff":
            security_report.append(("Content-Type/X-Content-Type-Options", "Небезопасное", "Средняя", "Установите заголовок 'X-Content-Type-Options' в 'nosniff' при предоставлении HTML-контента, чтобы предотвратить анализ типов MIME."))

        return security_report

    except requests.exceptions.RequestException as e:
        print(f"Ошибка: Не удалось получить URL: {e}")
        return []

def format_security_report(security_report):
    output = f"{'Заголовок':<30} {'Статус':<15} {'Уровень':<10} {'Рекомендация'}\n"
    output += "-" * 80 + "\n"

    for header, status, severity, recommendation in security_report:
        output += f"{header:<30} {status:<15} {severity:<10} {recommendation}\n"

    return output

if __name__ == "__main__":
    url = input("Введите URL для анализа:")
    security_report = analyze_headers(url)
    if security_report:
        print("\nОтчет о безопасности:")
        print(format_security_report(security_report))
    else:
        print("В запросе и ответе отсутствуют проблемы безопасности в заголовках.")
