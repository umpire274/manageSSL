from Classes.CertificateAuthority import CertificateAuthority
from Classes.CertificateCSRGenerator import CertificateCSRGenerator
from Classes.CertificateGenerator import CertificateGenerator
from Classes.CertificateUtilities import CertificateUtilities

menu_options = {
    1: 'Create new CA Certificate',
    2: 'Create new Certificate Request',
    3: 'Create new Certificate',
    4: 'Certificates Utilities',
    0: 'Exit',
}

utilities_options = {
    1: 'Check Certificate Request',
    2: 'Check Certificate',
    0: 'Back',
}


def print_menu():
    for key in menu_options.keys():
        if key == 0:
            print("-----------------------")
        print(key, '--', menu_options[key])


def print_submenu():
    for key in utilities_options.keys():
        if key == 0:
            print("---------------------------")
        print(key, '--', utilities_options[key])


def text(text_to_print, num_of_dots, num_of_loops):
    from time import sleep
    import keyboard
    import sys
    shell = sys.stdout
    shell.write(text_to_print)
    dotes = int(num_of_dots) * '.'
    for last in range(0, num_of_loops):
        for dot in dotes:
            keyboard.write(dot)
            sleep(0.2)


def clear_screen(secs):
    from time import sleep
    import os
    sleep(secs)
    # per windows
    if os.name == 'nt':
        os.system('cls')
    # per mac e linux(here, os.name is 'posix')
    else:
        os.system('clear')


def input_con_default(prompt, default):
    risposta = input(prompt)
    if risposta == '':
        return default
    else:
        return risposta


if __name__ == "__main__":

    print("\nHello Administrator.")

    while True:
        print("\nOperations with OpenSSL")
        print("-----------------------")
        print_menu()
        print("-----------------------")
        option = int(input('Enter your choice: '))
        match option:
            case 1:
                print('\n\n')
                # Request to user of parameters for new CA
                bites = int(
                    input_con_default('Enter the length of the encryption of the private key (in bites) [2048]: ',
                                      '2048'))
                def_md = input_con_default('Enter the default format of encryption (for example: sha256) [sha256]: ',
                                           'sha256')
                country = input_con_default('Enter the COUNTRY (two character format like IT) [IT]: ', 'IT')
                org = input_con_default('Enter the ORGANIZATION []: ', '')
                orgunit = input_con_default('Enter the ORGANIZATIONAL UNIT []: ', '')
                commonname = input_con_default('Enter the COMMON NAME of the CA []: ', '')
                print('\n')
                # end
                ca = CertificateAuthority()
                ca.create_config_file(bites, def_md, country, org, orgunit, commonname)
                if ca.proceed:
                    ca.generate_root_key(bites)
                    ca.create_csr()
                    expiration_days = int(input("Enter the expiration (days) of the certificate: "))
                    ca.create_self_signed_certificate(expiration_days)
                    text('Creating new CA', 5, 2)
                    print('Done.')
                    clear_screen(2)
                else:
                    print('\n\n-----------------------\nCreation new CA aborted\n-----------------------\n\n')
                    clear_screen(2)
                pass
            case 2:
                print('\n\n')
                # Request to user of parameters for new CA
                bites = int(
                    input_con_default('Enter the length of the encryption of the private key (in bites) [2048]: ',
                                      '2048'))
                country = input_con_default('Enter the COUNTRY (two character format like IT) []: ', '')
                state = input_con_default('Enter the STATE or PROVINCE (two character format like RM) []: ', '')
                locality = input_con_default('Enter the CITY []: ', '')
                org = input_con_default('Enter the ORGANIZATION []: ', '')
                orgunit = input_con_default('Enter the ORGANIZATIONAL UNIT []: ', '')
                commonname = input_con_default('Enter the COMMON NAME of the CA []: ', '')
                print('\n')
                generator = CertificateCSRGenerator(
                    key_length=bites,
                    country_name=country,
                    state_name=state,
                    locality_name=locality,
                    org_name=org,
                    org_unit_name=orgunit,
                    common_name=commonname
                )
                private_key = generator.generate_private_key(commonname)
                csr = generator.generate_csr(private_key, commonname)
                text('Creating new CSR request', 5, 2)
                print('Done.')
                clear_screen(2)
                pass
            case 3:
                generator = CertificateGenerator()
                generator.check_ca_ready()
                csr_file = input("Enter the CSR file name (without extension): ")
                # print_csr_info(csr_file)
                # validate_csr()
                valid_days = input_con_default('Enter the expiration (days) of the certificate [365]: ', '365')
                generator.generate_certificate(csr_file, valid_days)
                text('Creating new Certificate', 5, 2)
                print('Done.\n')
                print("-----------------------------------------")
                print(f"Certificate saved to {generator.crt_file}")
                print("-----------------------------------------\n")
                clear_screen(2)
                pass
            case 4:
                cert_utils = CertificateUtilities()
                while True:
                    print("\nUtilities with Certificates")
                    print("---------------------------")
                    print_submenu()
                    print("---------------------------")
                    suboption = int(input('Enter your choice: '))
                    match suboption:
                        case 1:
                            csr_file = input('Enter the name of certificate request to check: ')
                            if csr_file:
                                cert_utils.check_certificate_request(csr_file)
                            pass
                        case 2:
                            crt_file = input('Enter the name of certificate to check: ')
                            if crt_file:
                                cert_utils.check_certificate(crt_file)
                            pass
                        case 0:
                            break
                pass
            case 0:
                print("\n-------------------\nThank you for using")
                break
            case _:
                print("Invalid input")
