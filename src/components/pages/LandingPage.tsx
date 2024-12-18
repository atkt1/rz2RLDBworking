import React from 'react';
import Navbar from '@/components/layout/Navbar';
import Hero from '@/components/sections/home/Hero';
import Features from '@/components/sections/home/Features';
import Pricing from '@/components/sections/home/Pricing';
import TestingSection from '@/components/sections/home/TestingSection';
import Footer from '@/components/layout/Footer';

interface LandingPageProps {
  onLogin?: () => void;
  onSignUp?: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onLogin, onSignUp }) => {
  return (
    <div className="min-h-screen bg-white">
      <Navbar 
        onLogin={onLogin} 
        onSignUp={onSignUp} 
      />
      <main>
        <Hero onSignUp={onSignUp} onWatchVideo={() => {}} />
        <Features />
        <Pricing />
        <TestingSection />
      </main>
      <Footer />
    </div>
  );
};