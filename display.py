from colorama import init, Fore, Back, Style



print_unknown='?'


def print_mimo(ap):
    m_status=ap.get_mimo()

    if m_status == None:
        is_m=print_unknown
    else:
        if m_status == 'S':
            is_m=Fore.RED + m_status + Style.RESET_ALL
        elif m_status == 'MU':
            is_m=Fore.YELLOW + m_status + Style.RESET_ALL
        elif m_status == 'MU+':
            is_m=Fore.GREEN + m_status + Style.RESET_ALL

    return is_m

def print_w(ap):
    w_status, w_verified=ap.get_w()

    if w_status == None:
        is_w=print_unknown
    elif not w_status:
        is_w=Fore.RED + 'No' + Style.RESET_ALL
    else:
        if w_status == 'Optional':
            is_w=Fore.YELLOW + 'Opt' + Style.RESET_ALL
        else:
            is_w=Fore.GREEN + 'Req' + Style.RESET_ALL

        if not w_verified:
            is_w=is_w + Fore.BLUE + '*' + Style.RESET_ALL

    return is_w

def print_r(ap):
    r_status, r_verified=ap.get_r()

    if r_status == None:
        is_r=print_unknown
    elif not r_status:
        is_r=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_r=Fore.GREEN + r_status + Style.RESET_ALL

        if not r_verified:
            is_r=is_r + Fore.BLUE + '*' + Style.RESET_ALL

    return is_r

def print_s(ap):
    s_status=ap.get_s()

    if s_status == None:
        is_s=print_unknown
    elif not s_status:
        is_s=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_s=Fore.GREEN + 'Yes' + Style.RESET_ALL

    return is_s

def print_k(ap):
    k_status, k_verified=ap.get_k()
    
    if k_status == None:
        is_k=print_unknown
    elif not k_status:
        is_k=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_k=Fore.GREEN + 'Yes' + Style.RESET_ALL
        
        if not k_verified:
            is_k=is_k + Fore.BLUE + '*' + Style.RESET_ALL
    
    return is_k


def print_v(ap):
    v_status, v_verified=ap.get_v()
    
    if v_status == None:
        is_v=print_unknown
    elif not v_status:
        is_v=Fore.RED + 'No' + Style.RESET_ALL
    else:
        is_v=Fore.GREEN + 'Yes' + Style.RESET_ALL
        
        if not v_verified:
            is_v=is_v + Fore.BLUE + '*' + Style.RESET_ALL
    
    return is_v
