import userModel from './../models/userModel.js';


//ADD ITEM IN CART
const addToCart = async(req, res) =>{
    try {
        let userData = await userModel.findById(req.body.userId)
        let cartData = await userData.cartData;
        if(!cartData[req.body.itemId]){
            cartData[req.body.itemId] = 1;
        } else{
            cartData[req.body.itemId] += 1;
        }
        await userModel.findByIdAndUpdate(req.body.userId,{cartData})
        res.json({success:true, message:"Added to cart"})
    } catch (error) {
        console.log(error);
        res.json({success:false, message:"Error"})
    }
}

//REMOVE ITEM FROM CART
const removeFromCart = async(req, res) => {
    try {
        let userData = await userModel.findById(req.body.userId)
        let cartData = await userData.cartData
        if (cartData[req.body.itemId]>0) {
            cartData[req.body.itemId] -= 1;
        }
        await userModel.findByIdAndUpdate(req.body.userId,{cartData});
        res.json({success: true,message:"Removed from Cart"})
    } catch (error) {
        console.log(error);
        res.json({success:false, message:"error"})
        
    }
}

//GET USER CART DATA
const getCart = async(req, res) =>{
    try {
        let userData = await userModel.findById(req.body.userId);
        let cartData = userData.cartData;
        res.json({success: true, cartData})
    } catch (error) {
        console.log(error);
        res.json({success: false,message:"error"})
    }
}

export {addToCart, removeFromCart, getCart}