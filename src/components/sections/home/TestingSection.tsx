import React from 'react';
import { Shield } from 'lucide-react';
import { Button } from '@/components/ui/Button';

const TestingSection = () => {
  return (
    <section className="py-12 bg-blue-50">
      <div className="container mx-auto px-4">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
          <div className="lg:w-1/2">
            <h2 className="text-3xl md:text-4xl font-bold mb-6">
              Unlimited testing
              <br />
              until you go live
            </h2>
            <div className="space-y-3 mb-6">
              {[
                { text: '1:1 Onboarding Available' },
                { text: 'Amazon Compliance' },
                { text: 'Questions? Call us: (512) 960-2042' }
              ].map((item, index) => (
                <div key={index} className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-blue-600" />
                  <span className="text-gray-600">{item.text}</span>
                </div>
              ))}
            </div>
          </div>
          
          <div className="lg:w-1/2">
            <div className="flex gap-2">
              <input
                type="email"
                placeholder="ryan@mycompany.com"
                className="flex-1 px-4 py-3 rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <Button variant="primary" className="whitespace-nowrap bg-cyan-500 hover:bg-cyan-600">
                Start Now
              </Button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default TestingSection;