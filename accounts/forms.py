from django import forms
from .models import User


class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    confirm_password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = User
        fields = ['first_name', 'last_name',
                  'username', 'email', 'password']
        
    def clean(self):
        cleaned_data = super(UserForm, self).clean()
        password = cleaned_data.get('password')
        confirmPassword = cleaned_data.get('password')

        if password != confirmPassword:
            raise forms.ValidationError(
                "Password does not match"
            )


