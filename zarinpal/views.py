
from django.urls import reverse
from azbankgateways import bankfactories, models as bank_models, default_settings as settings


def go_to_gateway_view(request):
    # خواندن مبلغ از هر جایی که مد نظر است
    amount = 100000
    # تنظیم شماره موبایل کاربر از هر جایی که مد نظر است
    user_mobile_number = '+989050813873'  # اختیاری

    factory = bankfactories.BankFactory()

    # or factory.create(bank_models.BankType.BMI) or set identifier
    bank = factory.create()
    bank.set_request(request)
    bank.set_amount(amount)
    # یو آر ال بازگشت به نرم افزار برای ادامه فرآیند
    bank.set_client_callback_url(reverse('/callback-gateway'))
    bank.set_mobile_number(user_mobile_number)  # اختیاری

    # در صورت تمایل اتصال این رکورد به رکورد فاکتور یا هر چیزی که بعدا بتوانید ارتباط بین محصول یا خدمات را با این
    # پرداخت برقرار کنید.
    bank_record = bank.ready()

    # هدایت کاربر به درگاه بانک
    return bank.redirect_gateway()
