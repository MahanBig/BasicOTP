--[[
#####################################################################
SCRIPT MADE BY BASICID
Enjoy :)
#####################################################################
]]--

local OTP = {}
local HashLib = require(script.HashLib)

local function base32decode(base32)
	return HashLib.base32_decode(base32)
end

local function base32encode(binary)
	return HashLib.base32_encode(binary)
end

local function hmac(hashFunc, key, message)
	return HashLib.hmac(hashFunc, key, message, true)
end

local function urlencode(str)
	return str:gsub("([^%w])", function(c)
		return string.format("%%%02X", string.byte(c))
	end)
end

function OTP.generateTOTP(secret, timestep, digits, hashFunc)
	timestep = timestep or 30
	digits = digits or 6
	hashFunc = hashFunc or HashLib.sha1

	local counter = math.floor(os.time() / timestep)

	local decodedSecret = base32decode(secret)
	local message = string.pack(">I8", counter)
	local hmac = hmac(hashFunc, decodedSecret, message)
	local offset = string.byte(hmac, #hmac) % 16 + 1

	local byte1 = string.byte(hmac, offset)
	local byte2 = string.byte(hmac, offset + 1)
	local byte3 = string.byte(hmac, offset + 2)
	local byte4 = string.byte(hmac, offset + 3)

	byte1 = bit32.band(byte1, 0x7f)
	byte2 = bit32.band(byte2, 0xff)
	byte3 = bit32.band(byte3, 0xff)

	local code = 
		bit32.bor(
			bit32.lshift(byte1,24),
			bit32.lshift(byte2,16),
			bit32.lshift(byte3,8),
			bit32.lshift(byte4,0)
		)

	local otp = code % 10^digits

	return tostring(otp)
end

function OTP.generateHOTP(secret, counter, digits, hashFunc)
	digits = digits or 6
	hashFunc = hashFunc or HashLib.sha1

	local decodedSecret = base32decode(secret)
	local message = string.pack(">I8", counter)
	local hmac = hmac(hashFunc, decodedSecret, message)
	local offset = string.byte(hmac, #hmac) % 16 + 1

	local byte1 = string.byte(hmac, offset)
	local byte2 = string.byte(hmac, offset + 1)
	local byte3 = string.byte(hmac, offset + 2)
	local byte4 = string.byte(hmac, offset + 3)

	byte1 = bit32.band(byte1, 0x7f)
	byte2 = bit32.band(byte2, 0xff)
	byte3 = bit32.band(byte3, 0xff)

	local code = 
		bit32.bor(
			bit32.lshift(byte1,24),
			bit32.lshift(byte2,16),
			bit32.lshift(byte3,8),
			bit32.lshift(byte4,0)
		)

	local otp = code % 10^digits

	return tostring(otp)
end

function OTP.validateTOTP(secret, otp, timestep, digits, hashFunc, allowedDrift)
	timestep = timestep or 30
	digits = digits or 6
	allowedDrift = allowedDrift or 1
	hashFunc = hashFunc or HashLib.sha1
	local currentCounter = math.floor(os.time() / timestep)

	for i = -allowedDrift, allowedDrift do
		local counter = currentCounter + i
		if OTP.generateTOTP(secret, timestep, digits, hashFunc) == otp then
			return true
		end
	end

	return false
end

function OTP.validateHOTP(secret, otp, counter, digits, hashFunc)
	digits = digits or 6
	hashFunc = hashFunc or HashLib.sha1

	return OTP.generateHOTP(secret, counter, digits, hashFunc) == otp
end

function OTP.generateQRCodeURI(secret, account, issuer, algorithm, digits, timestep)
	algorithm = algorithm or "SHA1"
	digits = digits or 6
	timestep = timestep or 30
	local uri = string.format(
		"otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		urlencode(account),
		secret,
		urlencode(issuer),
		algorithm,
		digits,
		timestep
	)
	return uri
end

return OTP
