from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserChangeForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib import messages
from .models import UserProfile
from .forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMultiAlternatives
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string

def send_verification_email(user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    verification_link = reverse('verify_email', kwargs={'uidb64': uid, 'token': token})
    full_link = f'http://127.0.0.1:8000{verification_link}'

    subject = "Verify your email"
    message = render_to_string('email_verification.html', {'user': user, 'verification_link': full_link})

    email = EmailMultiAlternatives(subject, message, 'your_email@gmail.com', [user.email])
    email.attach_alternative(message, "text/html")
    email.send()

def register_view(request): 
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        role = request.POST.get('role')

        if not (first_name and last_name and username and email and password and confirm_password and role):
            messages.error(request, "Please fill all fields")
        elif password != confirm_password:
            messages.error(request, "Passwords do not match")
        elif User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
        else:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_active = False
            user.save()

            UserProfile.objects.create(user=user, role=role, is_verified=False)

            send_verification_email(user)
            messages.success(request, 'Account created successfully! Please check your email to verify your account.')
            return redirect('login')

    return render(request, 'register.html')

def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        
        user_profile = UserProfile.objects.get(user=user)
        user_profile.is_verified = True
        user_profile.save()
        
        messages.success(request, "Your email has been verified. You can now log in.")
        return redirect('login')
    else:
        messages.error(request, "Invalid or expired verification link.")
        return redirect('register')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            user_profile = UserProfile.objects.get(user=user)
            
            if not user_profile.is_verified:
                messages.error(request, "Your email is not verified. Please check your email.")
                return redirect('login')

            login(request, user)
            if user_profile.role == 'admin':
                return redirect('admin_dashboard')
            else:
                return redirect('user_dashboard')
        else:
            messages.error(request, 'Invalid username or password')
    
    return render(request, 'login.html')


def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

@login_required
def user_dashboard(request):
    return render(request, 'user_dashboard.html')

@login_required
def update_profile(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        

        if not username or not first_name or not last_name:
            messages.error(request, "All fields are required!")
        else:
            if User.objects.filter(username = username).exclude(id=request.user.id).exists():
                messages.error(request, "This username is already taken.")
            else:
                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.username = username
                request.user.save()

                update_session_auth_hash(request, request.user)
                messages.success(request, 'Your profile was successfully updated!')
                return redirect('user_dashboard')

    return render(request, 'update_profile.html')


@login_required
def manage_users(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role != 'admin':
            messages.error(request, 'Regular users do not have permission to access this page.')
            return redirect('user_dashboard')
    except UserProfile.DoesNotExist:
        messages.error(request, 'User profile not found.')
        return redirect('user_dashboard')

    users = User.objects.all()
    return render(request, 'manage_users.html', {'users': users})

@login_required
def delete_user(request, user_id):
    try:
        admin_profile = UserProfile.objects.get(user=request.user)
        if admin_profile.role != 'admin':
            messages.error(request, 'Regular users do not have permission to delete users.')
            return redirect('manage_users')

        user = User.objects.get(id=user_id)
        user.delete()
        messages.success(request, f'User {user.username} deleted successfully!')
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
    except UserProfile.DoesNotExist:
        messages.error(request, 'User profile not found.')

    return redirect('manage_users')

@login_required
def promote_demote_user(request, user_id):
    try:
        admin_profile = UserProfile.objects.get(user=request.user)
        if admin_profile.role != 'admin':
            messages.error(request, 'Regular users do not have permission to modify roles.')
            return redirect('manage_users')

        user = User.objects.get(id=user_id)
        user_profile = UserProfile.objects.get(user=user)

        if user.is_superuser:
            user.is_superuser = False
            user_profile.role = 'user'
            messages.success(request, f'{user.username} has been demoted to regular user.')
        else:
            user.is_superuser = True
            user_profile.role = 'admin'
            messages.success(request, f'{user.username} has been promoted to admin.')

        user.save()
        user_profile.save()

    except User.DoesNotExist:
        messages.error(request, 'User not found.')
    except UserProfile.DoesNotExist:
        messages.error(request, 'User profile not found.')

    return redirect('manage_users')

@login_required
def password_change(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            old_password = form.cleaned_data["old_password"]
            new_password = form.cleaned_data["new_password"]

            if not request.user.check_password(old_password):
                form.add_error("old_password", "Old password is incorrect.")
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)

                messages.success(request, "Your password has been updated.")
                return redirect("login")
    else:
        form = PasswordChangeForm()

    return render(request, "password_change.html", {"form": form})

def send_password_reset_email(user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    reset_link = reverse('reset_password_confirm', kwargs={'uidb64': uid, 'token': token})
    full_link = f'http://127.0.0.1:8000{reset_link}'

    subject = "Reset Your Password"
    message = render_to_string('password_reset_email.html', {'user': user, 'reset_link': full_link})

    email = EmailMultiAlternatives(subject, message, 'your_email@gmail.com', [user.email])
    email.attach_alternative(message, "text/html")
    email.send()

def reset_password_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
            send_password_reset_email(user)
            messages.success(request, "A password reset link has been sent to your email.")
        except User.DoesNotExist:
            messages.error(request, "No account found with this email.")

        return redirect('login')

    return render(request, 'reset_password_request.html')

def reset_password_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password != confirm_password:
                messages.error(request, "Passwords do not match.")
            else:
                user.set_password(new_password)
                user.save()
                messages.success(request, "Your password has been reset successfully. You can now log in.")
                return redirect('login')

        return render(request, 'reset_password_confirm.html')

    else:
        messages.error(request, "Invalid or expired password reset link.")
        return redirect('reset_password_request')