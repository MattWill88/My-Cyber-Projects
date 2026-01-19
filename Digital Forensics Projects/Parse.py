#import python libraries
from tkinter import *
from ttkbootstrap.scrolled import ScrolledText
from collections import Counter
import re
from tkinter import simpledialog
import pandas as pd

#code for main GUI window
window=Tk()
window.title('Apache log filter')
window.geometry('900x780')
#(code based on Bro Code, 2020)

#function extract ip address, timestamp, request type and response code
def parse_file():

    log_file='apacheaccess.log'
    file=open(log_file,'r')

    for line in file:
        lines=line.split(' ')

        ip=lines[0]
        timestamp=lines[3]
        request_type=lines[5]
        response_code=lines[8]
        filtered_info.insert(END, f"IP Address: {ip}, TimeStamp: {timestamp}, Request Type: {request_type}, Response Code: {response_code}\n")
        #(code based on Geeks for Geeks, 2024)

#function to filter log entries by start and end time chosen by the user
def show_log():

    log_file='apacheaccess.log'
    with open(log_file, 'r') as file:
        log_file = file.read()
        reg_exp = r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [\+\-]\d{4}\]'  #regular expression for timestamp
        timestamps= re.findall(reg_exp, log_file)
        #(code based on Red Eyed Coder Club, 2019)

        df=pd.DataFrame(timestamps)

        input1 = simpledialog.askstring("Enter Start Time", "Enter Start: ")
        input2 = simpledialog.askstring("Enter End Time", "Enter End: ")

        filtered_df = df.loc[(df[0] >= input1)
                            & (df[0] < input2)]

        timestamp_filter_list.insert(END, f"{filtered_df}\n")
        timestamp_filter_list.insert(END, f"Entries Total: {filtered_df.size}\n")
        timestamp_filter_list.insert(END, "---------------------------------------------------")
        #(code based on Geeks for Geeks, 2020)

#function to show the count of each ip address making a server request
def ip_count():

    log_file='apacheaccess.log'
    with open(log_file, 'r') as file:
        log_file=file.read()
        reg_exp=r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' #regular expression for ip addresses
        ip_addresses=re.findall(reg_exp, log_file)
        #(code based on Red Eyed Coder Club, 2019)

        ip_address_order = Counter(ip_addresses)
        ip_descending_order = sorted(ip_address_order.items(), key=lambda item: item[1], reverse=True)
        for ip_add, counter in ip_descending_order:
            ip_frequency_list.insert(END, f"IP: {ip_add}: Number of requests: {counter}\n")
        #(code based on W3resource, 2025)

#function to search an ip address and display list of requests made to server
def show_ip():

    log_file='apacheaccess.log'
    file=open(log_file)
    enter_ip=simpledialog.askstring("Enter IP Address", "Enter IP: ")
    #(code based on Tutorialspoint, 2024)

    for line in iter(file):
        ip=line.split(" - ")[0]
        if ip == enter_ip:
            ip_info.insert(END, line.split(']')[0]+'\n')
    ip_info.insert(END, "-----------------------------------------------------")
    #(code based on InfoSecAddicts, 2018)

#create GUI widgets

#filter ip, timestamp, response type and response code
filtered_info=ScrolledText(window, width=100, height=10)
filtered_info.pack()

filtered_info_button=Button(window, text='Parse File', command=parse_file)
filtered_info_button.pack()

#filter timestamps by start and end time
timestamp_filter_list=ScrolledText(window, width=100, height=10)
timestamp_filter_list.pack()

timestamp_filter_list_button=Button(window, text='Filter Timestamp info', command=show_log)
timestamp_filter_list_button.pack()

#show count of each ip address present in log
ip_frequency_list=ScrolledText(window, width=100, height=10)
ip_frequency_list.pack()

ip_frequency_list_button=Button(window, text='Show IP Count', command=ip_count)
ip_frequency_list_button.pack()

#show log entries for entered IP address
ip_info=ScrolledText(window, width=100, height=10)
ip_info.pack()

ip_info_button=Button(window, text='Show IP requests', command=show_ip)
ip_info_button.pack()

window.mainloop()
#(code based on Python Tutorial, 2021)
#(code based on Python Tutorial, 2015)
