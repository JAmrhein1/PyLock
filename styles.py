# styles.py

def configure_styles(style):
    # Custom frame style with matching background color
    style.configure('Custom.TFrame', background='#2C3E50')

    # Custom label style with matching background color
    style.configure('Custom.TLabel', background='#2C3E50', foreground='white', font=('Helvetica', 14))

    # Custom checkbutton style with matching background color
    style.configure('Custom.TCheckbutton', background='#2C3E50', foreground='white', font=('Helvetica', 12))

    # Custom button style
    style.configure('My.TButton', font=('Helvetica', 16, 'bold'), padding=15, relief='raised', borderwidth=4)
    style.map('My.TButton',
              background=[('active', '#5bc0de'), ('!active', '#5bc0de')],
              foreground=[('active', 'white'), ('!active', 'white')])

    # Configure Treeview styles with striped rows
    style.configure('Custom.Treeview', font=('Helvetica', 12), rowheight=30, background='#2C3E50', fieldbackground='#2C3E50', foreground='white')
    style.configure('Custom.Treeview.Heading', font=('Helvetica', 14, 'bold'), background='#5bc0de', foreground='white')
    style.map('Custom.Treeview', background=[('selected', '#5bc0de')])
