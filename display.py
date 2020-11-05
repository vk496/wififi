
print_unknown='?'


def print_mimo(ap):
    m_status=ap.get_mimo()

    if m_status == None:
        is_m=print_unknown
    else:
        if m_status == 'S':
            is_m=m_status
        elif m_status == 'MU':
            is_m=m_status
        elif m_status == 'MU+':
            is_m=m_status

    return is_m

def print_w(ap):
    w_status, w_verified=ap.get_w()

    if w_status == None:
        is_w=print_unknown
    elif not w_status:
        is_w='No'
    else:
        if w_status == 'Optional':
            is_w='Opt'
        else:
            is_w='Req'

        if not w_verified:
            is_w=is_w + '*'

    return is_w

def print_r(ap):
    r_status, r_verified=ap.get_r()

    if r_status == None:
        is_r=print_unknown
    elif not r_status:
        is_r='No'
    else:
        is_r=r_status

        if not r_verified:
            is_r=is_r + '*'

    return is_r

def print_s(ap):
    s_status=ap.get_s()

    if s_status == None:
        is_s=print_unknown
    elif not s_status:
        is_s='No'
    else:
        is_s='Yes'

    return is_s

def print_k(ap):
    k_status, k_verified=ap.get_k()
    
    if k_status == None:
        is_k=print_unknown
    elif not k_status:
        is_k='No'
    else:
        is_k='Yes'
        
        if not k_verified:
            is_k=is_k + '*'
    
    return is_k


def print_v(ap):
    v_status, v_verified=ap.get_v()
    
    if v_status == None:
        is_v=print_unknown
    elif not v_status:
        is_v='No'
    else:
        is_v='Yes'
        
        if not v_verified:
            is_v=is_v + '*'
    
    return is_v
