import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuthContext } from '@/context/AuthContext'
import { Button } from '@/components/common/Button'
import { 
  Shield, 
  Search, 
  History, 
  FileText, 
  Settings, 
  LogOut,
  Menu,
  Moon,
  Sun
} from 'lucide-react'
import { cn } from '@/utils/lib'

export function Header() {
  const { user, logout } = useAuthContext()
  const location = useLocation()
  const [isDarkMode, setIsDarkMode] = React.useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false)

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: Shield },
    { name: 'Scan', href: '/scan', icon: Search },
    { name: 'History', href: '/history', icon: History },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  React.useEffect(() => {
    // Check for saved theme preference or default to light mode
    const savedTheme = localStorage.getItem('theme')
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    const shouldBeDark = savedTheme === 'dark' || (!savedTheme && prefersDark)
    
    setIsDarkMode(shouldBeDark)
    document.documentElement.classList.toggle('dark', shouldBeDark)
  }, [])

  const toggleTheme = () => {
    const newTheme = !isDarkMode ? 'dark' : 'light'
    setIsDarkMode(!isDarkMode)
    document.documentElement.classList.toggle('dark', !isDarkMode)
    localStorage.setItem('theme', newTheme)
  }

  const handleLogout = async () => {
    await logout()
  }

  return (
    <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link to="/dashboard" className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="font-bold text-xl">OSINT Platform</span>
          </Link>
        </div>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center space-x-6">
          {navigation.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.href
            
            return (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  'flex items-center space-x-2 text-sm font-medium transition-colors hover:text-primary',
                  isActive ? 'text-primary' : 'text-muted-foreground'
                )}
              >
                <Icon className="h-4 w-4" />
                <span>{item.name}</span>
              </Link>
            )
          })}
        </nav>

        <div className="flex items-center space-x-4">
          {/* Theme Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleTheme}
            className="h-9 w-9 p-0"
          >
            {isDarkMode ? (
              <Sun className="h-4 w-4" />
            ) : (
              <Moon className="h-4 w-4" />
            )}
          </Button>

          {/* User Menu */}
          <div className="hidden md:flex items-center space-x-4">
            <div className="text-sm">
              <p className="font-medium">{user?.username}</p>
              <p className="text-muted-foreground text-xs">
                {user?.is_admin ? 'Administrator' : 'User'}
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleLogout}
              icon={<LogOut className="h-4 w-4" />}
            >
              Logout
            </Button>
          </div>

          {/* Mobile Menu Button */}
          <Button
            variant="ghost"
            size="sm"
            className="md:hidden h-9 w-9 p-0"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            <Menu className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Mobile Navigation */}
      {isMobileMenuOpen && (
        <div className="md:hidden border-t bg-background">
          <div className="container py-4 space-y-2">
            {navigation.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.href
              
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={() => setIsMobileMenuOpen(false)}
                  className={cn(
                    'flex items-center space-x-3 rounded-md px-3 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground',
                    isActive ? 'bg-accent text-accent-foreground' : 'text-muted-foreground'
                  )}
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.name}</span>
                </Link>
              )
            })}
            
            <div className="border-t pt-4 mt-4">
              <div className="px-3 py-2">
                <p className="font-medium">{user?.username}</p>
                <p className="text-muted-foreground text-xs">
                  {user?.is_admin ? 'Administrator' : 'User'}
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleLogout}
                className="w-full justify-start"
                icon={<LogOut className="h-4 w-4" />}
              >
                Logout
              </Button>
            </div>
          </div>
        </div>
      )}
    </header>
  )
}