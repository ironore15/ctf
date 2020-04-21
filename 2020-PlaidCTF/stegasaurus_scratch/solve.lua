function factorial(n)
  if n == 1 then
    return 1
  else
    return n * factorial(n - 1)
  end
end
function Alice1(hand)
  table.sort(hand)
  alices, sum = {0, 0, 0, 0, 0, 0, 0}, 0
  for i = 1, 8 do
    sum = sum + hand[i]
  end
  discarded = sum % 8 + 1
  permnum = (hand[discarded] - 1) // 8
  for i = 1, 8 do
    if i ~= discarded then
      alices[i - (i > discarded and 1 or 0)] = hand[i]
    end
  end
  for i = 1, 6 do
    swapi = (permnum % factorial(8 - i)) // factorial(7 - i) + i
    alices[i], alices[swapi] = alices[swapi], alices[i]
  end
  return alices
end
function Bob1(alices)
  bobs, sum = {0, 0, 0, 0, 0, 0, 0}, 0
  for i = 1, 7 do
    bobs[i] = alices[i]
    sum = sum + alices[i]
  end
  table.sort(bobs)
  permnum = 0
  for i = 1, 6 do
    for j = i, 7 do
      if alices[i] == bobs[j] then
        permnum = permnum + (j - i) * factorial(7 - i)
        bobs[i], bobs[j] = bobs[j], bobs[i]
        break
      end
    end
  end
  table.sort(bobs)
  bobs[0], bobs[8] = 0, 40001
  for i = permnum * 8 + 1, permnum * 8 + 8 do
    discarded = (sum + i) % 8 + 1
    if bobs[discarded - 1] < i and i < bobs[discarded] then
      return i
    end
  end
  return 0
end
function Alice2(table)
  rem = {}
  stack = 0
  for i = 96, 1, -1 do
    if table[i] == 2 then
      stack = stack + 1
    elseif stack ~= 0 then
      rem[#rem + 1] = i
      stack = stack - 1
    end
  end
  for i = 96, 1, -1 do
    if stack == 0 then
      break
    elseif table[i] == 1 then
      found = false
      for j = 1, #rem do
        if i == rem[j] then
          found = true
        end
      end
      if not found then
        rem[#rem + 1] = i
        stack = stack - 1
      end
    end
  end
  return rem
end
function Bob2(present)
  guess = {}
  stack = 0
  for i = 1, 96 do
    if present[i] == 0 then
      stack = stack + 1
    elseif stack ~= 0 then
      guess[#guess + 1] = i
      stack = stack - 1
    end
  end
  for i = 1, 96 do
    if stack == 0 then
      break
    elseif present[i] == 1 then
      found = false
      for j = 1, #guess do
        if i == guess[j] then
          found = true
        end
      end
      if not found then
        guess[#guess + 1] = i
        stack = stack - 1
      end
    end
  end
  return guess
end
