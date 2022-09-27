from django.contrib import admin
from django.urls import path

from azbankgateways.urls import az_bank_gateways_urls
from . import views

admin.autodiscover()


urlpatterns = [
    path('bankgateways/', az_bank_gateways_urls()),
    path('zarin/', views.go_to_gateway_view)

]
