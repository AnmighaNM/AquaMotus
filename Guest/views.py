from django.shortcuts import render
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from Guest.models import * 
import random
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.core.exceptions import ValidationError
from django.db.models import Avg
from django.http import JsonResponse
from django.contrib.auth import logout
from django.urls import reverse
from django.contrib.auth import get_user_model

# Create your views here.

def index(request):
    return render(request, 'Guest/index.html')

def login_view(request):
    return render(request, 'Guest/Login.html')  # Make sure the path matches your template

def forgetpassword(request):
    if request.method=="POST":
        otp=random.randint(10000, 999999)
        request.session["otp"]=otp
        request.session["femail"]=request.POST.get('Email')
        send_mail(
            'Respected Sir/Madam ',#subject
            "\rYour OTP for Reset Password is "+str(otp),#body
            settings.EMAIL_HOST_USER,
            [request.POST.get('Email')],
        )
        return redirect("WebGuest:Verification")
    else:
        return render(request,"Guest/ForgetPassword.html")

def OtpVerification(request):
    if request.method=="POST":
        otp=int(request.session["otp"])
        if int(request.POST.get('txtotp'))==otp:
            return redirect("WebGuest:Create")
    return render(request,"Guest/OTPVerification.html")

def CreateNewPass(request):
    User = get_user_model()
    if request.method=="POST":
        if request.POST.get('Npassword')==request.POST.get('Cpassword'):
            usercount=User.objects.filter(email=request.session["femail"]).count()
            if usercount>0:
                user=User.objects.get(email=request.session["femail"])
                Npassword = request.POST.get('Npassword')
                user.set_password(Npassword)
                user.save()
                messages.success(request, "Password updated successfully.")
                return redirect("WebGuest:Login")
    else:       
        return render(request,"Guest/CreateNewPassword.html")

def ajaxemail(request):
    User = get_user_model()
    usercount=User.objects.filter(user_email=request.GET.get("email")).count() 
    if usercount>0:
        return render(request,"Guest/Ajaxemail.html",{'mess':1})
    else:
         return render(request,"Guest/Ajaxemail.html")

def user_registration(request):
    if request.method == "POST":
        fname = request.POST.get("fName")
        lname = request.POST.get("LName")
        email = request.POST.get("Email")
        contact = request.POST.get("Contact")
        gender = request.POST.get("Gender")
        address = request.POST.get("Address")
        password = request.POST.get("Password")
        confirm_password = request.POST.get("re-password")
        photo = request.FILES.get("Photo")
        
        User = get_user_model()
        
        # Check if the username already exists
        if User.objects.filter(username=email).exists():
            messages.error(request, "Username already exists.")
            return render(request, "Guest/UserRegistration.html")
        
        # Optionally, check if the email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, "Guest/UserRegistration.html")
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "Guest/UserRegistration.html")

        # Server-side validation (additional checks)
        try:
            validate_contact(contact)
            validate_address(address)
            validate_photo(photo)

            # Check for duplicates
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already exists.")
                return render(request, "Guest/UserRegistration.html")
            if Profile.objects.filter(user_contact=contact).exists():
                messages.error(request, "Contact number already exists.")
                return render(request, "Guest/UserRegistration.html")

            # Create the user
            user = User.objects.create_user(
                username=email,  # using email as the username
                first_name=fname,
                last_name=lname,
                email=email,
                password=password,  # password is hashed by `create_user`
                role='user'
            )
            user.save()

            # Create the associated profile
            profile = Profile.objects.create(
                user=user,
                user_contact=contact,
                user_gender=gender,
                user_address=address,
                user_photo=photo,
            )
            profile.save()

            messages.success(request, "Registration successful!")
            return redirect("WebGuest:Login")

        except ValidationError as e:
            messages.error(request, str(e))

    return render(request, "Guest/UserRegistration.html")

def validate_contact(contact):
    if not contact.isdigit() or not contact.startswith(('6', '7', '8', '9')) or len(contact) != 10:
        raise ValidationError("Invalid contact number. Contact must be a 10-digit number starting with 6, 7, 8, or 9.")

def validate_address(address):
    if not all(x.isalnum() or x.isspace() or x in ",." for x in address):
        raise ValidationError("Address can only contain letters, numbers, spaces, commas, and periods.")

def validate_photo(photo):
    if not photo.name.endswith(('.jpg', '.jpeg', '.png')):
        raise ValidationError("Photo must be in JPG or PNG format.")
    
    
# View to handle email validation and send OTP
def validate_email(request):
    if request.method == "POST":
        email = request.POST.get('email')
        
        User = get_user_model()
        
        # Check if the email already exists in the system
        if User.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'message': 'Email already exists!'})

        # Generate OTP and send email
        otp = random.randint(100000, 999999)  # 6-digit OTP
        
        subject = "Your OTP for email verification"
        message = f"Your OTP is {otp}"
        recipient_list = [email]
        
        try:
            # Send the OTP email
            send_mail(subject, message, settings.EMAIL_HOST_USER, recipient_list)

            # Store OTP and email in the session
            request.session['otp'] = otp
            request.session['email'] = email

            return JsonResponse({'success': True, 'message': 'OTP sent successfully!'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    return JsonResponse({'success': False, 'message': 'Invalid request'})

# View to verify the OTP
def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')

        # Retrieve OTP from session
        session_otp = request.session.get('otp')
        
        if session_otp and str(entered_otp) == str(session_otp):
            # OTP is correct, perform any further actions if needed
            # Optionally clear the session
            del request.session['otp']
            del request.session['email']
            
            return JsonResponse({'success': True, 'message': 'OTP verified successfully'})
        else:
            return JsonResponse({'success': False, 'message': 'Invalid OTP'})
    
    return JsonResponse({'success': False, 'message': 'Invalid request'})

def logoutView(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('WebGuest:Index')  # Replace 'LogoutPage' with the name of the URL pattern for your logout page