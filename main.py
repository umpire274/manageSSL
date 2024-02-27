from Classes.CertificateAuthority import CertificateAuthority

menu_options = {
    1: 'Create new CA Certificate',
    2: 'Create new Certificate Request',
    3: 'Create new Certificate',
    4: 'Exit',
}


def print_menu():
    for key in menu_options.keys():
        print(key, '--', menu_options[key])


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

    print("Hello Administrator.\n")
    print("Operations on OpenSSL")
    print("---------------------")

    while True:
        print_menu()
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
            case 2:
                text('Creating new CSR request', 5, 2)
            case 3:
                text('Creating new Certificate', 5, 2)
            case 4:
                print("\n-------------------\nThank you for using")
                exit(0)
            case _:
                print("Invalid input")