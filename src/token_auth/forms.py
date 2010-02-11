from django import forms
from token_auth.models import ProtectedURLToken

class ProtectedURLTokenForm(forms.Form):
    url = forms.CharField(max_length=255)
    valid_until = forms.DateField(required=False)
    emails = forms.CharField(max_length=255)
    forward_count = forms.IntegerField(required=False)
    
    def clean_emails(self):
        emails = self.cleaned_data['emails'].split(';')
        return emails
        
class ProtectedURLTokenAddForm(forms.ModelForm):
    class Meta:
        model = ProtectedURLToken
        fields = ('name','email','forward_count')


class ForwardProtectedURLForm(forms.Form):
    
    def __init__(self, token, *args, **kwargs):
        super(ForwardProtectedURLForm, self).__init__(*args, **kwargs)
        self.token = token
    
    emails = forms.CharField(max_length=255)
    
    def clean_emails(self):
        emails = self.cleaned_data['emails'].split(';')
        if self.token.can_forward:
            if len(emails) > self.token.forward_count:
                raise forms.ValidationError("You can only forward to %i emails." % self.token.forward_count)
        return emails