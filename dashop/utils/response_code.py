class RETCODE:
    # OK                  = "0"               # OK
    # IMAGECODEERR        = "4001"            # 图像代码错误
    # THROTTLINGERR       = "4002"            # 节流错误 ???
    # NECESSARYPARAMERR   = "4003"            # 必要参数错误
    # USERERR             = "4004"            # 用户错误
    # PWDERR              = "4005"            # 密码错误
    # CPWDERR             = "4006"            # 重复密码错误
    # MOBILEERR           = "4007"            # 手机号码错误
    # SMSCODERR           = "4008"
    # ALLOWERR            = "4009"
    # SESSIONERR          = "4101"            # session错误
    # DBERR               = "5000"            # 数据库错误
    # EMAILERR            = "5001"            # 邮件错误
    # TELERR              = "5002"            # 电话号码错误
    # NODATAERR           = "5003"            # 数据缺失错误
    # NEWPWDERR           = "5004"            # 新密码错误
    # OPENIDERR           = "5005"            # ID错误
    # PARAMERR            = "5006"            # 参数错误
    # STOCKERR            = "5007"            # 库存错误

    # 请求成功
    OK              = "0"

    # 请求参数相关
    PARAMERR        = "7001"        # 参数错误
    SESSIONERR      = "7002"        # session错误

    # 用户信息相关
    USERERR         = "8001"        # 用户信息
    PASSWORDERR     = "8002"        # 收货地址无效
    NEWPASSWORDERR  = "8003"        # 新密码错误
    MOBILEERR       = "8004"        # 手机号错误
    EMAILERR        = "8005"        # 邮箱账号错误
    TELERR          = "8006"        # 电话号码错误

    # 数据库相关
    DBERR           = "9001"        # 数据库错误
    IMGERR          = "9002"        # 图片信息错误
    STOCKERR        = "9003"        # 库存错误
