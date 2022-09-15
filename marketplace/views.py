from multiprocessing import context
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from .context_processors import get_cart_counter

from vendor.models import Vendor
from menu.models import Category, FoodItem
from django.db.models import Prefetch
from .models import Cart


# Create your views here.


def marketplace(request):
    vendors = Vendor.objects.filter(is_approved=True, user__is_active=True)
    vendor_count = vendors.count()
    context = {'vendors': vendors, 'vendor_count': vendor_count}
    return render(request, 'marketplace/listings.html', context)


def vendor_detail(request, vendor_slug):
    vendor = get_object_or_404(Vendor, vendor_slug=vendor_slug)

    categories = Category.objects.filter(vendor=vendor).prefetch_related(
        Prefetch(
            'fooditems',
            queryset=FoodItem.objects.filter(is_available=True),

        )
    )
    if request.user.is_authenticated:
        cart_items = Cart.objects.filter(user=request.user)
    else:
        cart_items = None

    context = {'vendor': vendor, 'categories': categories,
               'cart_items': cart_items}
    return render(request, 'marketplace/vendor_detail.html', context)


def add_to_cart(request, food_id):
    if request.user.is_authenticated:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            # Check if the food item exists
            try:
                fooditem = FoodItem.objects.get(id=food_id)
                # Check if the user has already added the food to the cart
                try:
                    chkCart = Cart.objects.get(
                        user=request.user, fooditem=fooditem)
                    # increase the cart quantity
                    chkCart.quantity += 1
                    chkCart.save()
                    return JsonResponse({'status': 'Success', 'message': 'Increased the card!', 'cart_counter': get_cart_counter(request), 'qty': chkCart.quantity})

                except:
                    chkCart = Cart.objects.create(
                        user=request.user, fooditem=fooditem, quantity=1)
                    return JsonResponse({'status': 'Success', 'message': 'Added The Food Card', 'cart_counter': get_cart_counter(request), 'qty': chkCart.quantity})
            except:
                return JsonResponse({'status': 'Failed', 'message': 'This Food does not exist!'})
        else:
            return JsonResponse({'status': 'Failed', 'message': 'invalid request!'})
    else:
        return JsonResponse({'status': 'login_required', 'message': 'Please login first!'})


def decrease_cart(request, food_id):
    if request.user.is_authenticated:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            # Check if the food item exists
            try:
                fooditem = FoodItem.objects.get(id=food_id)
                # Check if the user has already added the food to the cart
                try:
                    chkCart = Cart.objects.get(
                        user=request.user, fooditem=fooditem)
                    # deacrease the cart quantity
                    if chkCart.quantity > 1:
                        chkCart.quantity -= 1
                        chkCart.save()
                    else:
                        chkCart.delete()
                        chkCart.quantity = 0

                    return JsonResponse({'status': 'Success', 'cart_counter': get_cart_counter(request), 'qty': chkCart.quantity})

                except:

                    return JsonResponse({'status': 'Failed', 'message': 'you do not have the item in your Cart'})
            except:
                return JsonResponse({'status': 'Failed', 'message': 'This Food does not exist!'})
        else:
            return JsonResponse({'status': 'Failed', 'message': 'invalid request!'})
    else:
        return JsonResponse({'status': 'login_required', 'message': 'Please login first!'})


def cart(request):
    cart_items = Cart.objects.filter(user=request.user)
    context = {'cart_items': cart_items}
    return render(request, 'marketplace/cart.html', context)
