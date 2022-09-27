from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="check_zar"),
    path('pay', views.pay),
    path('verify', views.verify),
    path('transactions', views.transactions)
]