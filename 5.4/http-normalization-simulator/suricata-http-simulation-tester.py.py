import re
from urllib.parse import unquote_plus


class SuricataSimulator:

    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        parsed_rule = self.parse_rule(rule)
        if parsed_rule:
            self.rules.append(parsed_rule)

    def parse_rule(self, rule):
        # Very simplified rule parsing
        match = re.match(
            r'alert\s+http\s+\$HOME_NET\s+any\s+->\s+\$EXTERNAL_NET\s+any\s+\((.+)\)',
            rule)
        if match:
            options = match.group(1).split(';')
            parsed_options = {}
            for option in options:
                option = option.strip()
                if ':' in option:
                    key, value = option.split(':', 1)
                    parsed_options[key.strip()] = value.strip()
                else:
                    parsed_options[
                        option] = True  # Options without values are treated as flags
            return parsed_options
        return None

    def normalize_http_post(self, headers, body):
        # Normalize headers
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Decode URL-encoded body
        decoded_body = unquote_plus(body)

        # Parse content-type
        content_type = normalized_headers.get('content-type', '')
        if 'application/x-www-form-urlencoded' in content_type:
            # Parse form data
            form_data = {}
            for pair in decoded_body.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    form_data[key] = value
            return normalized_headers, form_data
        else:
            # For other content types, return the decoded body as is
            return normalized_headers, decoded_body

    def check_http_post(self, headers, body):
        normalized_headers, normalized_body = self.normalize_http_post(
            headers, body)

        alerts = []
        for rule in self.rules:
            if 'content' in rule:
                content = rule['content'].strip('"')
                if isinstance(normalized_body, dict):
                    # Check in form data
                    for value in normalized_body.values():
                        if content in value:
                            alerts.append(
                                f"Alert: {rule.get('msg', 'Unknown alert')}")
                elif content in normalized_body:
                    alerts.append(f"Alert: {rule.get('msg', 'Unknown alert')}")

            if 'http_header' in rule:
                header, value = rule['http_header'].split(':', 1)
                if header.lower() in normalized_headers and value.strip(
                        '"') in normalized_headers[header.lower()]:
                    alerts.append(f"Alert: {rule.get('msg', 'Unknown alert')}")

        return alerts


# Example usage
simulator = SuricataSimulator()

# Add some rules
simulator.add_rule(
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SQL Injection Attempt"; content:"UNION SELECT"; sid:1000001; rev:1;)'
)
simulator.add_rule(
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"XSS Attempt"; content:"<script>"; sid:1000002; rev:1;)'
)
simulator.add_rule(
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious User-Agent"; http_header:"User-Agent: HaxorBot"; sid:1000003; rev:1;)'
)

# Test cases
test_cases = [{
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    },
    "body":
    "username=admin&password=UNION%20SELECT%20password%20FROM%20users"
}, {
    "headers": {
        "Content-Type": "application/json",
        "User-Agent": "HaxorBot"
    },
    "body": '{"message": "<script>alert(\'XSS\');</script>"}'
}, {
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    },
    "body": "comment=This%20is%20a%20normal%20comment"
}]

# Run tests
for i, test in enumerate(test_cases, 1):
    print(f"Test Case {i}:")
    alerts = simulator.check_http_post(test['headers'], test['body'])
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No alerts triggered")
    print()
