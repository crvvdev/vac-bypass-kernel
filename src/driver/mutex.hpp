/******************************************************************************
    MIT License

    Copyright (c) 2024 Ricardo Carvalho

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 ******************************************************************************/
#pragma once

namespace Mutex
{
class Resource
{
  public:
    /// <summary>
    /// Initialize ERESOURCE
    /// </summary>
    /// <returns></returns>
    [[nodiscard]] NTSTATUS Initialize();

    /// <summary>
    /// Destrou ERESOURCE
    /// </summary>
    void Destroy();

    /// <summary>
    /// Acquires exclusive lock
    /// </summary>
    void LockExclusive();

    /// <summary>
    /// Acquires shared lock
    /// </summary>
    void LockShared();

    /// <summary>
    /// Unlock
    /// </summary>
    void Unlock();

    /// <summary>
    /// Get ERESOURCE
    /// </summary>
    /// <returns>ERESOURCE pointer</returns>
    __forceinline auto &GetResource() const
    {
        return this->_resource;
    }

  private:
    bool _initialized = false;
    LONG _refCount = 0;
    PERESOURCE _resource = nullptr;
};

} // namespace Mutex