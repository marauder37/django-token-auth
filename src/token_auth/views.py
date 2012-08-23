import time, datetime

from django.views.generic.simple import direct_to_template
from django.views.generic import list_detail
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.template.loader import render_to_string
from django.conf import settings
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.utils.http import cookie_date
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth.models import User

from reportlab.lib.units import mm
from reportlab.graphics.barcode import code128
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from forms import TokenAddForm, ForwardProtectedURLForm, ProtectedURLForm
from models import Token, ProtectedURL
from signals import signal_token_used, signal_token_visited

from django.contrib import messages

TOKEN_COOKIE = 'protectedurltokens'


def get_tokens_from_cookie(request):
    tokens = request.COOKIES.get(TOKEN_COOKIE, None)
    tokens_list = (tokens and tokens.split('|') or [])
    tokens_list = list(set(tokens_list))
    return tokens_list


def user_has_token_cookie(request, token_str=None):
    if not token_str is None:
        tokens = request.COOKIES.get(TOKEN_COOKIE, '')
        tokens_list = (tokens and tokens.split('|') or [])
        if token_str in tokens_list:
            return True
    return False


@user_passes_test(lambda u: u.has_perm('token_auth.add_token'))
def create_token(request, url_id=None, **kwargs):
    kwargs['extra_context'] = {}
    if request.method == 'POST':
        form = TokenAddForm(request.POST)
        if form.is_valid():
            email=form.cleaned_data['email']
            token = Token(
                url=form.cleaned_data['url'],
                valid_until=form.cleaned_data['valid_until'],
                forward_count=form.cleaned_data['forward_count'],
                email=email,
                name=form.cleaned_data['name'],
            )
            token.save()
            messages.add_message(request, messages.SUCCESS, 'Token successfully created for %s.' % token.email)
            return HttpResponseRedirect(reverse('token_list'))
    else:
        initial_data = None
        if not url_id is None:
            url = ProtectedURL.objects.get(id=url_id)
            initial_data = {'url': url.url, }
        form = TokenAddForm( initial=initial_data )
    kwargs['extra_context']['form'] = form
    return direct_to_template(request, template='token_auth/create_token.html', **kwargs)


@user_passes_test(lambda u: u.has_perm('token_auth.add_protectedurl'))
def protect_url(request, **kwargs):
    kwargs['extra_context'] = {}
    if request.method == 'POST':
        form = ProtectedURLForm(request.POST)
        if form.is_valid():
            protected_url = ProtectedURL( url=form.cleaned_data['url'] )
            protected_url.save()
            return HttpResponseRedirect(reverse('token_list'))
    else:
        form = ProtectedURLForm()
    kwargs['extra_context']['form'] = form
    return direct_to_template(request, template='token_auth/protect_url.html', **kwargs)


@user_passes_test(lambda u: u.has_perm('token_auth.add_protectedurl'))
def delete_protected_url(request, url_id=None, **kwargs):
    try:
        url = ProtectedURL.objects.get(pk=url_id)
        url.delete()
    except:
        pass
    return HttpResponseRedirect(reverse('token_list'))
    

@user_passes_test(lambda u: u.has_perm('token_auth.add_protectedurl'))
def delete_token(request, token_str=None, **kwargs):
    try:
        token = Token.objects.get(token=token_str)
        token.delete()
    except:
        pass
    return HttpResponseRedirect(reverse('expired_token_list'))
    

def forward_token(request, token_str=None, **kwargs):
    kwargs['extra_context'] = {}
    error = None
    token = get_object_or_404(Token, token=token_str)
    user_tokens = get_tokens_from_cookie(request)
    if not token.can_forward:
        error = _("Apologies! This token can not be forwarded.")
    else:
        if request.user.is_staff:
            pass
        elif not token.token in user_tokens:
            error = _("Apologies! You are not allowed to forward this token.")
    kwargs['extra_context']['token'] = token
    kwargs['extra_context']['error'] = error
    if not error:
        if request.method == 'POST':
            form = ForwardProtectedURLForm(token, request.POST)
            if form.is_valid():
                if token.forward_count:
                    token.forward_count = token.forward_count - len(form.cleaned_data['emails'])
                    token.save()
                for email in form.cleaned_data['emails']:
                    forwarded_token = Token( url=token.url, valid_until=token.valid_until, forward_count=0, email=email )
                    forwarded_token.save()
                    forwarded_token.send_token_email()
                return HttpResponseRedirect(reverse('token_list'))
        else:
            form = ForwardProtectedURLForm(token)
        kwargs['extra_context']['form'] = form
    return direct_to_template(request, template='token_auth/forward_token.html', **kwargs)



def use_token(request, token_str=None, **kwargs):
    if not token_str is None:
        #print "use_token: {}".format(token_str)
        token = get_object_or_404(Token, token=token_str)
        response = HttpResponseRedirect(token.url)
        if True or not token.used:
            # our tokens are not single use so never lock them out
            response = HttpResponseRedirect(token.url)
            token.used = True
            token.save()
            signal_token_used.send(sender=use_token, request=request, token=token)
            max_age = 2592000
            expires_time = time.time() + max_age
            expires = cookie_date(expires_time)
            tokens_list = list(set(get_tokens_from_cookie(request) + [token.token]))
            tokens = '|'.join(tokens_list)
            response.set_cookie(TOKEN_COOKIE, tokens, max_age=max_age, expires=expires)
        # if token is used but user doesn't have token cookie so tell them NO
        elif not user_has_token_cookie(request, token_str=token.token):
            response = HttpResponseRedirect(
                reverse('token_used', kwargs={'token_str':token.token,}))
        # cookie's expired... answer is still no
        elif not token.valid_until is None and token.valid_until <= datetime.datetime.now():
            response = HttpResponseRedirect(reverse('token_expired'))
        # user has a cookie with that token and it's still valid
        elif token.single_use:
            token.delete()
        signal_token_visited.send(sender=use_token, request=request, token=token)
        return response
    else:
        return direct_to_template(request, template='token_auth/token_invalid.html', **kwargs)


@user_passes_test(lambda u: u.has_perm('token_auth.add_token'))
def expire_token(request, token_str=None, **kwargs):
    response = HttpResponseRedirect(reverse('token_list'))
    if not token_str is None:
        max_age = 2592000
        expires_time = time.time() - max_age
        expires = cookie_date(expires_time)
        token = Token.objects.get(token__exact=token_str)
        token.valid_until = datetime.datetime.now()
        token.save()
        response.set_cookie(TOKEN_COOKIE, '', max_age=max_age, expires=expires)
    else:
        pass
    return response


def token_logout(request, **kwargs):
    """Remove all tokens then forward to the standard logout page"""
    response = HttpResponseRedirect(reverse('logout_form'))
    max_age = 2592000
    expires_time = time.time() - max_age
    expires = cookie_date(expires_time)
    response.set_cookie(TOKEN_COOKIE, '', max_age=max_age, expires=expires)
    return response


def token_barcode(request, token_str):
    try:
        token = Token.objects.get(token=token_str)
    except:
        return HttpResponseRedirect(reverse('token_invalid'))

    width = 85.6*mm
    height = 53.98*mm
    
    xoffset = 62*mm
    yoffset = 220*mm
    
    barcode_value = "####" + token_str
    if token.valid_until:
        expiry = token.valid_until.strftime("%d %h %Y")
    else:
        expiry = "Permanent"
        
    try:
        user = User.objects.get(email=token.email)
        name = "{} {}".format(user.first_name, user.last_name)
    except User.DoesNotExist:
        user = None
        name = "No user record for token, authority invalid"
        expiry = "not valid"
    
    response = HttpResponse(mimetype='application/pdf')
    response['Content-Disposition'] = 'filename={}.pdf'.format(token_str)

    p = canvas.Canvas(response, pagesize=A4, bottomup=True)
    p.roundRect(xoffset, yoffset, width-2, height-2, 3*mm)

    p.setFont("Helvetica", 12)
    p.drawString(xoffset+3*mm, yoffset+height-6*mm, "GT-EX Global Transportation")

    p.setFont("Helvetica", 16)
    p.drawString(xoffset+3*mm, yoffset+height-13*mm, "Driver Authority")

    p.setFont("Helvetica", 12)
    p.drawString(xoffset+3*mm, yoffset+height-25*mm, name)
    p.drawString(xoffset+3*mm, yoffset+height-36*mm, "Valid until: {}".format(expiry))

    barcode = code128.Code128(barcode_value
        , barWidth=.25*mm, barHeight=8*mm, lquiet=5*mm, rquiet=5*mm)    
    barcode.drawOn(p, xoffset+(width - barcode.width)/2, yoffset+5*mm)

    p.showPage()
    p.save()

    return response
    

def token_barcode_old(request, token_str):
    text = "####"+token_str
    bc = createBarcodeDrawing('Code128'
        , value=text,  barWidth=1.6*mm, barHeight=60*mm, humanReadable=True)
    dwg = Drawing(bc.width, bc.height)
    dwg.add(bc, name='barcode')
    response = HttpResponse(mimetype='image/png')
    response['Content-Disposition'] = 'filename={}.png'.format(token_str)
    response.write(dwg.asString('png'))
    return response
    

def token_used(request, template='token_auth/token_used.html', token_str=None, **kwargs):
    if not token_str is None:
        extra_context={'token_str': token_str, }
    return direct_to_template(request, template, extra_context=extra_context, **kwargs)


def token_expired(request, template='token_auth/token_expired.html', token_str=None, **kwargs):
    if not token_str is None:
        extra_context={'token_str': token_str, }
    return direct_to_template(request, template, extra_context=extra_context, **kwargs)


def token_invalid(request, template='token_auth/token_invalid.html', token_str=None, **kwargs):
    if not token_str is None:
        extra_context={'token_str': token_str, }
    return direct_to_template(request, template, extra_context=extra_context, **kwargs)


@user_passes_test(lambda u: u.has_perm('token_auth.add_token'))
def token_list(request):
    url_list = ProtectedURL.objects.all()
    return list_detail.object_list(
        request,
        queryset = Token.active_objects.all().order_by('name'),
        template_name = 'token_auth/token_list.html',
        template_object_name = 'token',
        allow_empty = True,
        extra_context = {'url_list': url_list, 'request': request}
        )


@user_passes_test(lambda u: u.has_perm('token_auth.add_token'))
def expired_token_list(request):
    return list_detail.object_list(
        request,
        queryset = Token.expired_objects.all().order_by('url'),
        template_name = 'token_auth/expired_token_list.html',
        template_object_name = 'token',
        allow_empty = True,
        )


@user_passes_test(lambda u: u.has_perm('token_auth.add_token'))
def send_email(request, token_str=None, **kwargs):
    if not token_str is None:
        token = get_object_or_404(Token, token=token_str)
        subject = render_to_string('token_auth/token_email_subject.txt', { 'token': token } )
        subject = ''.join(subject.splitlines())
        message = render_to_string('token_auth/token_email_message.txt', { 'token': token, 'http_host': request.META, 'sender': request.user } )
        message_html = render_to_string('token_auth/token_email_message.html', { 'token': token, 'http_host': request.META, 'sender': request.user } )
        #EmailMessage(subject=subject, body=message, to=(token.email,)).send()
        msg = EmailMultiAlternatives(subject, message, to=(token.email,))
        msg.attach_alternative(message_html, "text/html")
        msg.send()
        messages.add_message(request, messages.SUCCESS, 'Message successfully sent to %s.' % token.email)
        return HttpResponseRedirect(reverse('token_list'))
        
