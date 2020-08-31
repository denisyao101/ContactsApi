from django.urls import path
from .views import ContactList, ContactDetails

urlpatterns = [
    path('', ContactList.as_view(), name='contact-list'),
    path('<int:pk>/', ContactDetails.as_view(), name='contact-details'),
]
