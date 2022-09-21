from time import time
from tkinter import BooleanVar, IntVar, StringVar, Tk, ttk, Text
from tkinter.constants import END
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showinfo

import socket
import base64
import time
import pynetstring

# To DO => 1. Shortcut menu for Dev Server and Ksi Server; 2. Memes preview; 3. Handle if meme path is not selected;


def server_comunication(ip: str, port: int, nick_name: str, pwd: str, desc: str, nsfw: bool, meme_path: str) -> str:
    # Main Chanell Communication
    # Main Chanell Communication
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_main:
        try:
            s_main.connect((ip, port))
        except:
            return 'Server Error! (Unable to connect to the server)'
        # Init Comunication
        s_main.sendall(pynetstring.encode('C MTP V:1.0'))
        print('Client:  ' + 'C MTP V:1.0')
        # Confirm Init
        confirmation = pynetstring.decode(s_main.recv(1024))[0].decode('utf-8')
        if confirmation == 'S MTP V:1.0':
            print('Server:  ' + confirmation)
            # Send Nick
            s_main.sendall(pynetstring.encode('C ' + nick_name))
            print('Client:  ' + 'C ' + nick_name)
            # Recieve token
            token_response = pynetstring.decode(s_main.recv(1024))[
                0].decode('utf-8')
            if 'S ' in token_response:
                token = token_response.replace('S ', '')
                print('Server:  ' + token_response)
                # Recieve port
                port_response = pynetstring.decode(s_main.recv(1024))[
                    0].decode('utf-8')
                if 'S ' in port_response:
                    port_data = port_response.replace('S ', '')
                    print('Server:  ' + port_response)
                    # Data Channel Communication
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_data:
                        try:
                            s_data.connect((ip, int(port_data)))
                        except:
                            return 'Server Error! (Unable to connect to Data Chanell - might be wrong port)'
                        # Send Nick
                        s_data.sendall(pynetstring.encode('C ' + nick_name))
                        print('Client:  ' + 'C ' + nick_name)
                        # Recieve Token
                        token_verefication_response = pynetstring.decode(s_data.recv(1024))[
                            0].decode('utf-8')
                        if 'S ' in token_verefication_response:
                            token_verefication = token_verefication_response.replace(
                                'S ', '')
                            print('Server:  ' + token_verefication_response)
                            # Validate Token
                            if token_verefication == token:
                                # Recieve data request (MEME)
                                data_req = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data (MEME)
                                meme = base64.b64encode(
                                    open(meme_path, "rb").read()).decode("ascii")
                                s_data.sendall(pynetstring.encode('C ' + meme))
                                print('Client:  ' + 'C <meme>')
                                # Recieve Response (Data Lenght)
                                meme_lenght = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + meme_lenght)

                                # Recieve data request PWD
                                data_req = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data
                                s_data.sendall(pynetstring.encode('C ' + pwd))
                                print('Client:  C <password>')
                                # Recieve Response (Data Lenght)
                                pwd_lenght = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + pwd_lenght)

                                # Recieve data request (Description)
                                data_req = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data
                                s_data.sendall(pynetstring.encode('C ' + desc))
                                print('Client:  ' + 'C ' + desc)
                                # Recieve Response (Data Lenght)
                                desc_lenght = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + desc_lenght)

                                # Recieve data request (NSFW)
                                data_req = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8')
                                print('Server:  ' + data_req)
                                # Send Data
                                s_data.sendall(pynetstring.encode(
                                    'C ' + str(nsfw).lower()))
                                print('Client:  C ' + str(nsfw).lower())
                                # Recieve Response (Data Lenght)
                                nsfw_lenght = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8').replace('S ACK:', '')
                                print('Server:  S ' + nsfw_lenght)
                                # Recieve dToken
                                d_token_response = pynetstring.decode(s_data.recv(1024))[
                                    0].decode('utf-8')
                                d_token = d_token_response.replace(
                                    'S END:', '')
                                print('Server:  ' + d_token_response)
                            else:
                                return 'Server Error! (Tokens doesn\'t match)'
                            # Recieve Response (Finall Lenght)
                            finall_lenght_response = pynetstring.decode(s_main.recv(1024))[
                                0].decode('utf-8')
                            if not 'S ' in finall_lenght_response:
                                return 'Server Error! ' + finall_lenght_response
                            finall_lenght = finall_lenght_response.replace(
                                'S ', '')
                            print('Server:  ' + finall_lenght_response)
                            sum_lenght = int(
                                meme_lenght) + int(pwd_lenght) + int(desc_lenght) + int(nsfw_lenght)
                            if int(finall_lenght) == sum_lenght:
                                # Send dToken
                                s_main.sendall(
                                    pynetstring.encode('C ' + d_token))
                                print('Client:  ' + 'C ' + d_token)
                                # Recieve End Message
                                end_msg = pynetstring.decode(s_main.recv(1024))[
                                    0].decode('utf-8')
                                if end_msg == 'S ACK':
                                    print(end_msg)
                                    return 'Meme Uploaded Successfully!!!'
                                else:
                                    return 'Server Error! ' + end_msg
                            else:
                                print(str(finall_lenght) +
                                      '!=' + str(sum_lenght))
                                return 'Server Error! (Data Corruption)'
                        else:
                            return 'Server Error! ' + token_verefication_response
                else:
                    return 'Server Error! ' + port_response
            else:
                return 'Server Error! ' + token_response
        else:
            return 'Server Error!' + confirmation


def gui():

    def delete_uploading_msg_log():
        for child in uploading_msg_frame.winfo_children():
            child.destroy()
        window.update()

    def delete_msg_log():
        for child in msg_log_frame.winfo_children():
            child.destroy()
        window.update()

    def msg_log(msg: str):
        delete_msg_log()
        msg_log = ttk.Label(msg_log_frame, text=msg)
        msg_log.pack()

    def browse_memes():
        global meme_path
        meme_path = askopenfilename(filetypes=(
            ('png files', '*.png'), ('jpg files', '*.jpg')))
        meme_label = ttk.Label(main_frame, text=meme_path)
        meme_label.grid(row=7, column=1, columnspan=4)

    def send_meme():
        ip_val = ip.get().rstrip().replace("'", '\'')
        nick_val = nick.get().rstrip().replace("'", '\'')
        pwd_val = pwd.get().rstrip().replace("'", '\'')
        desc_val = desc_text.get(1.0, END).rstrip().replace("'", '\'')
        nsfw_val = nsfw.get().rstrip()
        try:
            port_val = int(port.get().rstrip())
        except:
            msg_log('Warning: Port has to be INTEGER')
            return
        if nsfw.get() == '':
            nsfw_val = 'false'
        # Check if all fields are not empty
        try:
            meme_path
        except:
            msg_log('Warning: Pick your MEME')
            return
        if ip_val == '' or port_val == '' or nick_val == '' or pwd_val == '' or desc_val == '' or meme_path == '':
            msg_log('Warning: None of the fields can be empty')
        else:
            delete_msg_log()
            uploading_label = ttk.Label(
                uploading_msg_frame, text='Uploading MEME (Please wait...)')
            uploading_label.pack()
            window.update()
            server_response = server_comunication(
                ip_val, port_val, nick_val, pwd_val, desc_val, nsfw_val, meme_path)
            msg_log(server_response)
            delete_uploading_msg_log()

    def shortcut_dev():
        ip.set('159.89.4.84')
        port.set('42069')
        window.update()

    def shortcut_main():
        ip.set('159.89.4.84')
        port.set('42070')
        window.update()

    window = Tk()

    window.geometry('600x350')
    window.resizable(0, 0)
    window.title('MTP Client')

    # MSG LOG
    msg_log_frame = ttk.Frame(window)
    msg_log_frame.pack()
    # Uploading Message Log - I had to do it this way because of the bug I encountered
    uploading_msg_frame = ttk.Frame(window)
    uploading_msg_frame.pack()

    # Input Frame
    main_frame = ttk.Frame(window)
    main_frame.pack()

    # IP Input
    ip = StringVar()
    ip_input = ttk.Entry(main_frame, textvariable=ip)
    ip_input.grid(row=1, column=2)
    # IP Label
    ip_label = ttk.Label(main_frame, text='IP Adress: ')
    ip_label.grid(row=1, column=1)

    # Port Input
    port = StringVar()
    port_input = ttk.Entry(main_frame, textvariable=port)
    port_input.grid(row=1, column=4)
    # Port Label
    port_label = ttk.Label(main_frame, text='Port: ')
    port_label.grid(row=1, column=3)

    # Nick Input
    nick = StringVar()
    nick_input = ttk.Entry(main_frame, textvariable=nick)
    nick_input.grid(row=2, column=2)
    # Nick Label
    nick_label = ttk.Label(main_frame, text='Nick: ')
    nick_label.grid(row=2, column=1)

    # Password Input
    pwd = StringVar()
    pwd_input = ttk.Entry(main_frame, textvariable=pwd)
    pwd_input.grid(row=2, column=4)
    # Nick Label
    pwd_label = ttk.Label(main_frame, text='Password: ')
    pwd_label.grid(row=2, column=3)

    # Shortcuts
    shorcut_frame = ttk.Frame(main_frame)
    shorcut_frame.grid(row=3, column=1, columnspan=4)
    # Shortcuts Buttons
    shortcut_btn_one = ttk.Button(
        shorcut_frame, text='Dev Server', command=shortcut_dev)
    shortcut_btn_one.grid(row=1, column=1, padx=10)
    shortcut_btn_two = ttk.Button(
        shorcut_frame, text='Main Server', command=shortcut_main)
    shortcut_btn_two.grid(row=1, column=2, padx=10)

    # Check Button
    nsfw = StringVar()
    nsfw_chceckbox = ttk.Checkbutton(
        main_frame, text='NSFW', variable=nsfw, onvalue='true', offvalue='false')
    nsfw_chceckbox.grid(row=4, column=1)

    # Description Label
    desc_label = ttk.Label(main_frame, text='Description:')
    desc_label.grid(row=5, column=1)
    # Description Textarea
    desc_text = Text(main_frame, width=50, height=5)
    desc_text.grid(row=6, column=1, columnspan=4)

    # Browse Button
    browse_button = ttk.Button(main_frame, text='Browse', command=browse_memes)
    browse_button.grid(row=8, column=1)

    # Send Button
    send_button = ttk.Button(window, text='Send MEME', command=send_meme)
    send_button.pack(side='bottom', anchor='e', padx=15, pady=15)

    window.mainloop()


def main():
    gui()


if __name__ == '__main__':
    main()
